-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking Promotion Policy.
--
-- Two modes:
--   observe — evaluate candidates, log would_promote, do not touch executor.
--   evaluate candidates and actually install passing candidates into
--           kernel nftables via the executor.
--
-- Runs as a worker 0 periodic callback. Consumes evidence from
-- shared-dict counters and evaluates loose/strict thresholds.

local _M = {}

local ir = require "core.ip_reputation"
local sm = require "core.kernel_blocking.state_machine"
local evidence = require "core.kernel_blocking.evidence"
local desired = require "core.kernel_blocking.desired_state"
local config = require "core.config"
local ttl_ladder = require "core.kernel_blocking.ttl_ladder"
local token_bucket = require "core.kernel_blocking.token_bucket"

local function detect_family(ip)
    if type(ip) == "string" and ip:find(":", 1, true) then
        return "ipv6"
    end
    return "ipv4"
end

-- Reserved / non-global special addresses that must never enter DROP sets.
local function is_reserved_address(ip, family)
    if type(ip) ~= "string" or ip == "" then
        return true, "invalid"
    end
    family = family or detect_family(ip)
    if family == "ipv4" then
        if ip == "0.0.0.0" then return true, "unspecified" end
        if ip:match("^127%.") then return true, "loopback" end
        if ip:match("^169%.254%.") then return true, "link_local" end
        local o1 = tonumber(ip:match("^(%d+)%."))
        if o1 and o1 >= 224 and o1 <= 239 then return true, "multicast" end
        if ip == "255.255.255.255" then return true, "broadcast" end
    else
        local lower = ip:lower()
        if lower == "::" then return true, "unspecified" end
        if lower == "::1" then return true, "loopback" end
        -- fe80::/10 link-local, ff00::/8 multicast
        if lower:match("^fe[89ab]") or lower:match("^fe80:") then
            return true, "link_local"
        end
        if lower:match("^ff") then return true, "multicast" end
    end
    return false, nil
end

-- Token bucket functions are provided by core.kernel_blocking.token_bucket.
-- This module uses microunits (1 token = 1,000,000 µu) for precision
-- and supports hot-reload of rate params with burst clamp (Design §6.2).

-- ---------------------------------------------------------------------------
-- Security gate: returns true if IP is safe to consider for promotion.
-- @param ip string
-- @param family string: "ipv4" or "ipv6"
-- @returns bool, reason
-- ---------------------------------------------------------------------------
local function passes_security_gate(ip, family)
    local kb_cfg = config.kernel_ip_blocking
    if not kb_cfg then return false, "no_config" end

    family = family or detect_family(ip)

    -- Feature enabled
    if kb_cfg.enabled ~= true then return false, "disabled" end

    -- Address family check
    if family == "ipv6" and not (kb_cfg.ipv6 and kb_cfg.ipv6.enabled) then
        return false, "family"
    end
    if family == "ipv4" and not (kb_cfg.ipv4 and kb_cfg.ipv4.enabled) then
        return false, "family"
    end

    -- Reserved/special addresses
    local reserved, why = is_reserved_address(ip, family)
    if reserved then return false, why or "reserved" end

    -- Whitelist check
    if ir.is_whitelisted(ip) then return false, "whitelisted" end

    -- Topology check: observe mode collects data regardless of topology;
    -- enforce mode requires topology=direct (validated at config save time).
    if kb_cfg.mode == "enforce" and kb_cfg.topology ~= "direct" then
        return false, "topology"
    end

    return true, nil
end

local function capacity_available(list)
    local kb_cfg = config.kernel_ip_blocking or {}
    local max_entries = kb_cfg.max_entries or {}
    local limit
    if list == "scanner_drop" then
        limit = tonumber(max_entries.scanner) or 100000
    elseif list == "cc_drop" then
        limit = tonumber(max_entries.cc) or 50000
    else
        limit = tonumber(max_entries.manual) or 10000
    end
    local n
    if desired.count_by_list then
        n = desired.count_by_list(list)
    else
        n = desired.count_desired()
    end
    if n >= limit then
        return false, n, limit
    end
    return true, n, limit
end

-- Exported for API / tests
_M.passes_security_gate = passes_security_gate
_M.is_reserved_address = is_reserved_address
_M.detect_family = detect_family
_M.capacity_available = capacity_available

---------------------------------------------------------------------------
-- Check if an IP is already installed in any automatic DROP set and return
-- the set name. Used for scanner/CC overlap resolution.
-- Design §5.1: scanner_drop > cc_drop.
-- @return string|nil: "scanner_drop" | "cc_drop" | nil
---------------------------------------------------------------------------
local function get_installed_auto_set(ip)
	local s = sm.get(ip)
	if not s or s.state ~= "installed" then return nil end
	if s.list == "scanner_drop" or s.list == "cc_drop" then
		return s.list
	end
	return nil
end

---------------------------------------------------------------------------
-- Enforce-mode promotion for a single scanner IP.
-- Consumes a token and calls executor.add() to install into kernel.
-- Design §6.6: stepped TTL renewal on repeated attacks (never shortens).
-- @return true on success or rate-limit, false on executor error
---------------------------------------------------------------------------
local function enforce_promote_scanner(ip, block_hits, flagged)
    -- Emergency pause: stop installing but keep observing
    local kb_cfg = config.kernel_ip_blocking
    local evidence_tbl = {
        strict = true, block_hits = block_hits, flagged = flagged,
    }
    if kb_cfg.emergency_pause then
        evidence_tbl.result = "paused"
        sm.upsert(ip, "scanner", "candidate", evidence_tbl, {})
        return true
    end

	local cap_ok = capacity_available("scanner_drop")
	if not cap_ok then
		evidence_tbl.result = "capacity_exceeded"
		sm.upsert(ip, "scanner", "rejected", evidence_tbl, {})
		return true
	end

	local existing = sm.get_policy(ip, "scanner") or sm.get(ip)
	local existing_cc = sm.get_policy(ip, "cc")
	local executor_cleanup = get_installed_auto_set(ip) == "cc_drop"

	-- Design §6.6 stepped TTL
	local ir_cfg = config.ip_reputation or {}
	local steps, max_ttl = ttl_ladder.steps_for_policy("scanner", kb_cfg, ir_cfg)
	local prior_count = 0
	if existing and existing.promotion_count then
		prior_count = tonumber(existing.promotion_count) or 0
	end
	local existing_expires = existing and existing.expires_at
	-- Prefer longer of scanner/cc remaining when upgrading from cc
	if existing_cc and existing_cc.expires_at then
		if not existing_expires or existing_cc.expires_at > existing_expires then
			existing_expires = existing_cc.expires_at
		end
	end
	local canary_ttl = nil
	if prior_count == 0 and not (existing and existing.state == "installed")
		and kb_cfg.canary and kb_cfg.canary.enabled == true then
		canary_ttl = kb_cfg.canary.scanner_ttl
	end
	local plan = ttl_ladder.plan({
		steps = steps,
		max_ttl = max_ttl,
		promotion_count = prior_count,
		existing_expires_at = existing_expires,
		canary_ttl = canary_ttl,
		now = ngx.time(),
	})
	-- Already installed at this/higher ladder rung: no-op (no token).
	if existing and existing.state == "installed" and existing.list == "scanner_drop"
		and not plan.extends then
		return true
	end

        -- Consume enforce token only when we will extend desired/kernel state.
	if not plan.extends then
		-- First-time path should always extend; if not, nothing to do.
		return true
	end
    if not token_bucket.consume_enforce() then
        evidence_tbl.result = "rate_limited"
        sm.upsert(ip, "scanner", "rate_limited", evidence_tbl, {})
        return true
    end

	local ttl = plan.ttl
	local family = detect_family(ip)
	evidence_tbl.ttl_tier = plan.tier
	evidence_tbl.ttl_reason = plan.reason
	evidence_tbl.promotion_count = plan.next_promotion_count
    -- dispatch_pending directly (skip intermediate "promoted" to avoid stuck state on crash)
    sm.upsert(ip, "scanner", "dispatch_pending", evidence_tbl, {
        list = "scanner_drop",
        family = family,
    })

    -- Install via executor
    local executor = require "core.kernel_blocking.executor"
    local exec = executor.get_executor()
    local call_ok, add_ok, add_err = pcall(function()
        return exec.add("scanner_drop", family, ip, ttl)
    end)

    if not call_ok then
        ngx.log(ngx.ERR, "kernel_blocking: executor.add crashed for ", ip, ": ",
            tostring(add_ok))
        evidence_tbl.result = "executor_error"
        evidence_tbl.error = tostring(add_ok)
        sm.upsert(ip, "scanner", "degraded", evidence_tbl, {
            list = "scanner_drop",
            family = family,
        })
        return false
    end

    if not add_ok then
        ngx.log(ngx.ERR, "kernel_blocking: executor.add returned false for ",
            ip, ": ", tostring(add_err))
        evidence_tbl.result = "executor_error"
        evidence_tbl.error = tostring(add_err)
        sm.upsert(ip, "scanner", "degraded", evidence_tbl, {
            list = "scanner_drop",
            family = family,
        })
        return false
    end

	-- Success: desired_state + state machine installed
	evidence_tbl.result = (plan.reason == "stepped_renewal") and "renewed" or "promoted"
	desired.set_desired(ip, family, "scanner_drop", evidence_tbl, ttl, {
		source = "automatic",
		policy = "scanner",
		reason = plan.reason,
		reconciliation_mode = "ensure",
		promotion_count = plan.next_promotion_count,
		ttl_tier = plan.tier,
	})
	-- scanner supersedes cc desired entry
	desired.remove_desired(ip, family, "cc_drop")
	sm.upsert(ip, "scanner", "installed", evidence_tbl, {
		list = "scanner_drop",
		family = family,
		installed_at = (existing and existing.installed_at) or ngx.time(),
		expires_at = plan.expires_at,
		promotion_count = plan.next_promotion_count,
		ttl_tier = plan.tier,
	})

	-- Remove from cc_drop if it was there (scanner_drop > cc_drop)
	if executor_cleanup then
		pcall(function()
			exec.delete("cc_drop", family, ip)
		end)
		sm.transition(ip, "cc", "cleared", {
			reason = "superseded_by_scanner",
			cleared_at = ngx.time(),
		})
	end

	ngx.log(ngx.WARN, "kernel_blocking: IP ", ip,
		" scanner_drop ", plan.reason, " ttl=", ttl, "s tier=", plan.tier,
		" count=", plan.next_promotion_count)
	return true
end

-- ---------------------------------------------------------------------------
-- Evaluate SCANNER candidates.
-- Reads scanner evidence from shared dict, evaluates loose/strict thresholds.
-- In observe mode: only logs "would_*" results.
-- In enforce mode: actually installs passing candidates via executor.
-- ---------------------------------------------------------------------------
local function evaluate_scanner_candidates()
    local seen = {}
    local work = {}

    local candidates = sm.list_candidates(0, 100)
    for _, c in ipairs(candidates.entries) do
        if c.policy == "scanner" and c.ip and not seen[c.ip] then
            seen[c.ip] = true
            work[#work + 1] = c.ip
        end
    end
    -- Design §6.6: also re-evaluate installed scanner entries for stepped renewal.
    local installed = sm.list(0, 200, "installed", "scanner")
    for _, e in ipairs(installed.entries or {}) do
        if e.ip and e.list == "scanner_drop" and not seen[e.ip] then
            seen[e.ip] = true
            work[#work + 1] = e.ip
        end
    end

    for _, ip in ipairs(work) do
        -- Security gate
        local family = detect_family(ip)
        local gate_ok, reason = passes_security_gate(ip, family)
        if not gate_ok then
            sm.upsert(ip, "scanner", "rejected", { reason = reason }, {})
            goto continue
        end

        -- Lifecycle evidence cutoff (Design §10.5)
        do
            local ok_life, life = pcall(require, "core.kernel_blocking.lifecycle")
            if ok_life and life and life.evidence_allowed then
                local allowed, why = life.evidence_allowed("scanner", ngx.time())
                if not allowed then
                    sm.upsert(ip, "scanner", "candidate", {
                        result = "evidence_cutoff",
                        reason = why,
                    }, {})
                    goto continue
                end
            end
        end

        -- Aggregate scanner evidence
        local block_hits = evidence.sum_scanner_blocks(ip)
        local flagged = ir.is_flagged and ir.is_flagged(ip) or false

        -- Loose threshold: >= 1 block hit in window
        local loose = block_hits >= 1

        -- Strict threshold: flagged AND >= min_hard_blocks
        local min_hard = (config.kernel_ip_blocking and
            config.kernel_ip_blocking.scanner and
            config.kernel_ip_blocking.scanner.min_hard_blocks) or 3
        local strict = flagged and (block_hits >= min_hard)

        -- Rate-limit gate:
        --   observe mode  -> check virtual observe bucket (no consumption)
        --   enforce mode  -> check enforce bucket (consumed in enforce_promote_*)
        local mode = config.kernel_ip_blocking.mode
        local observe_limited = not token_bucket.observe_has_token()

        local ev = {
            strict = strict, loose = loose,
            block_hits = block_hits, flagged = flagged,
        }

        if mode == "enforce" then
            -- Enforce mode: install when strict. enforce_promote_scanner
            -- consumes the enforce token; if bucket empty, marks rate_limited.
            if strict then
                enforce_promote_scanner(ip, block_hits, flagged)
            else
                -- Keep installed entries as-is when evidence cooled off.
                local cur = sm.get_policy(ip, "scanner")
                if not (cur and cur.state == "installed") then
                    ev.result = "would_not_promote"
                    sm.upsert(ip, "scanner", "candidate", ev, {})
                end
            end
        else
            -- Observe mode (default): log only, using virtual observe bucket.
            if strict and not observe_limited then
                ev.result = "would_promote"
                sm.upsert(ip, "scanner", "candidate", ev, {})
            elseif strict and observe_limited then
                ev.result = "would_rate_limit"
                sm.upsert(ip, "scanner", "candidate", ev, {})
            else
                ev.result = "would_not_promote"
                sm.upsert(ip, "scanner", "candidate", ev, {})
            end
        end

        ::continue::
    end
end

-- ---------------------------------------------------------------------------
-- Enforce-mode promotion for a single CC IP.
-- Design §6.6: stepped TTL (default 300→600→1800), never shortens.
-- ---------------------------------------------------------------------------
local function enforce_promote_cc(ip, violation_count)
	local kb_cfg = config.kernel_ip_blocking

	-- Emergency pause: stop installing but keep observing
	if kb_cfg.emergency_pause then
		sm.upsert(ip, "cc", "candidate",
			{ result = "paused", violation_count = violation_count }, {})
		return true
	end

	local cap_ok = capacity_available("cc_drop")
	if not cap_ok then
		sm.upsert(ip, "cc", "rejected",
			{ result = "capacity_exceeded", violation_count = violation_count }, {})
		return true
	end

	-- Check overlap: if already in scanner_drop, no need for cc_drop
	local existing_set = get_installed_auto_set(ip)
	if existing_set == "scanner_drop" then
		sm.upsert(ip, "cc", "candidate",
			{ result = "already_in_scanner_drop", violation_count = violation_count }, {})
		return true
	end

	local existing = sm.get_policy(ip, "cc")
	local steps, max_ttl = ttl_ladder.steps_for_policy("cc", kb_cfg, config.ip_reputation)
	local prior_count = 0
	if existing and existing.promotion_count then
		prior_count = tonumber(existing.promotion_count) or 0
	end
	local canary_ttl = nil
	if prior_count == 0 and not (existing and existing.state == "installed")
		and kb_cfg.canary and kb_cfg.canary.enabled == true then
		canary_ttl = kb_cfg.canary.cc_ttl
	end
	local plan = ttl_ladder.plan({
		steps = steps,
		max_ttl = max_ttl,
		promotion_count = prior_count,
		existing_expires_at = existing and existing.expires_at,
		canary_ttl = canary_ttl,
		now = ngx.time(),
	})

	if existing and existing.state == "installed" and existing.list == "cc_drop"
		and not plan.extends then
		return true
	end
	if not plan.extends then
		return true
	end

	-- Consume enforce token only when extending
	if not token_bucket.consume_enforce() then
		sm.upsert(ip, "cc", "rate_limited",
			{ violation_count = violation_count }, {})
		return true
	end

	local ttl = plan.ttl
	local family = detect_family(ip)
	local ev_tbl = {
		violation_count = violation_count,
		ttl_tier = plan.tier,
		ttl_reason = plan.reason,
		promotion_count = plan.next_promotion_count,
	}
	sm.upsert(ip, "cc", "dispatch_pending", ev_tbl, {
		list = "cc_drop",
		family = family,
	})

	-- Install via executor
	local executor = require "core.kernel_blocking.executor"
	local exec = executor.get_executor()

	local call_ok, add_ok, add_err = pcall(function()
		return exec.add("cc_drop", family, ip, ttl)
	end)

	if not call_ok then
		ngx.log(ngx.ERR, "kernel_blocking: executor.add crashed for CC ", ip, ": ",
			tostring(add_ok))
		ev_tbl.result = "executor_error"
		ev_tbl.error = tostring(add_ok)
		sm.upsert(ip, "cc", "degraded", ev_tbl, {
			list = "cc_drop",
			family = family,
		})
		return false
	end

	if not add_ok then
		ngx.log(ngx.ERR, "kernel_blocking: executor.add false for CC ", ip,
			": ", tostring(add_err))
		ev_tbl.result = "executor_error"
		ev_tbl.error = tostring(add_err)
		sm.upsert(ip, "cc", "degraded", ev_tbl, {
			list = "cc_drop",
			family = family,
		})
		return false
	end

	-- Success: desired_state + installed
	ev_tbl.result = (plan.reason == "stepped_renewal") and "renewed" or "promoted"
	desired.set_desired(ip, family, "cc_drop", ev_tbl, ttl, {
		source = "automatic",
		policy = "cc",
		reason = plan.reason,
		reconciliation_mode = "ensure",
		promotion_count = plan.next_promotion_count,
		ttl_tier = plan.tier,
	})
	sm.upsert(ip, "cc", "installed", ev_tbl, {
		list = "cc_drop",
		family = family,
		installed_at = (existing and existing.installed_at) or ngx.time(),
		expires_at = plan.expires_at,
		promotion_count = plan.next_promotion_count,
		ttl_tier = plan.tier,
	})

	ngx.log(ngx.WARN, "kernel_blocking: IP ", ip,
		" cc_drop ", plan.reason, " ttl=", ttl, "s tier=", plan.tier,
		" count=", plan.next_promotion_count, " violations=", violation_count)
	return true
end

-- ---------------------------------------------------------------------------
-- Evaluate CC candidates.
-- Reads CC violation evidence from shared dict and evaluates candidates.
-- Design §6.4: requires min_violation_windows consecutive violations.
-- ---------------------------------------------------------------------------
local function evaluate_cc_candidates()
	local kb_cfg = config.kernel_ip_blocking
	if not (kb_cfg.cc and kb_cfg.cc.enabled) then return end
	if not (kb_cfg.cc.rule_ids and #kb_cfg.cc.rule_ids > 0) then return end

	-- CC observe-only: global observe OR cc.enforce_ready=false
	local cc_enforce = (kb_cfg.mode == "enforce") and
		(kb_cfg.cc.enforce_ready == true)

	local candidates = sm.list_candidates(0, 100)
	local min_windows = (kb_cfg.cc.min_violation_windows) or 3
	local rule_window = (kb_cfg.cc.ttl) or 300  -- use ttl as window base

	local seen = {}
	local work = {}
	for _, c in ipairs(candidates.entries) do
		if c.policy == "cc" and c.ip and not seen[c.ip] then
			seen[c.ip] = true
			work[#work + 1] = c.ip
		end
	end
	-- Design §6.6: re-evaluate installed CC for stepped renewal.
	local installed = sm.list(0, 200, "installed", "cc")
	for _, e in ipairs(installed.entries or {}) do
		if e.ip and e.list == "cc_drop" and not seen[e.ip] then
			seen[e.ip] = true
			work[#work + 1] = e.ip
		end
	end

	for _, ip in ipairs(work) do
		-- Also skip if already in scanner_drop (higher priority)
		local existing_scanner = sm.get_policy(ip, "scanner")
		if existing_scanner and existing_scanner.state == "installed" and existing_scanner.list == "scanner_drop" then
			sm.upsert(ip, "cc", "candidate",
				{ result = "already_in_scanner_drop" }, {})
			goto continue
		end

		-- Security gate
		local family = detect_family(ip)
		local gate_ok, reason = passes_security_gate(ip, family)
		if not gate_ok then
			sm.upsert(ip, "cc", "rejected", { reason = reason }, {})
			goto continue
		end

		-- Lifecycle evidence cutoff (Design §10.5)
		do
			local ok_life, life = pcall(require, "core.kernel_blocking.lifecycle")
			if ok_life and life and life.evidence_allowed then
				local allowed, why = life.evidence_allowed("cc", ngx.time())
				if not allowed then
					sm.upsert(ip, "cc", "candidate", {
						result = "evidence_cutoff",
						reason = why,
					}, {})
					goto continue
				end
			end
		end

        -- Count violation windows
        local violations = evidence.count_cc_violations(ip, rule_window, min_windows + 2)

        -- Design §6.4: require_challenge_fail for strict CC promotion.
        local require_cf = true
        if kb_cfg.cc and kb_cfg.cc.require_challenge_fail == false then
            require_cf = false
        end
        local has_cf = true
        if require_cf then
            has_cf = evidence.has_challenge_fail and evidence.has_challenge_fail(ip) or false
        end

        local mode = kb_cfg.mode
        -- CC candidate observability: check virtual observe bucket for "would_rate_limit"
        local observe_limited = not token_bucket.observe_has_token()

        local strict_ready = violations >= min_windows and has_cf
        if cc_enforce and strict_ready then
            -- CC enforce: enforce_promote_cc consumes the enforce token
            enforce_promote_cc(ip, violations)
        elseif violations >= min_windows and not has_cf then
            sm.upsert(ip, "cc", "candidate", {
                violation_count = violations,
                result = "missing_challenge_fail",
            }, {})
        elseif violations >= min_windows and not observe_limited then
            -- Observe: candidate would promote if enforce_ready were true
            sm.upsert(ip, "cc", "candidate",
                { violation_count = violations, result = "would_promote" }, {})
        elseif violations >= min_windows and observe_limited then
            sm.upsert(ip, "cc", "candidate",
                { violation_count = violations, result = "would_rate_limit" }, {})
        else
			local cur = sm.get_policy(ip, "cc")
			if not (cur and cur.state == "installed") then
				local result_str = "would_not_promote"
				if mode ~= "enforce" then
					result_str = (cc_enforce and "cc_observe") or "cc_observe_only"
				end
				sm.upsert(ip, "cc", "candidate",
					{ violation_count = violations, result = result_str }, {})
			end
		end

		::continue::
	end
end

-- ---------------------------------------------------------------------------
-- Main evaluate function (worker 0 callback entry point).
-- Already called within the kernel_blocking-enabled gate.
-- ---------------------------------------------------------------------------
function _M.evaluate(_now)
	local kb_cfg = config.kernel_ip_blocking
	if not kb_cfg then return end

	if kb_cfg.scanner and kb_cfg.scanner.enabled then
		evaluate_scanner_candidates()
	end

	if kb_cfg.cc and kb_cfg.cc.enabled then
		evaluate_cc_candidates()
	end
end

-- ---------------------------------------------------------------------------
-- Module init: exports for worker 0 timer wiring in core.init.
-- ---------------------------------------------------------------------------
function _M.process_candidates(now)
    if not (config.kernel_ip_blocking and config.kernel_ip_blocking.enabled) then
        return
    end
    -- Evidence cutoff: only post-transition evidence is eligible.
    -- lifecycle module loaded on demand for evidence enforcement
    pcall(require, "core.kernel_blocking.lifecycle")
    -- Refill observe-bucket tokens before evaluation round (Design §6.2)
    token_bucket.refill_observe()
    -- In enforce mode, also refill the enforce bucket
    if config.kernel_ip_blocking.mode == "enforce" then
        token_bucket.refill_enforce()
    end
    _M.evaluate(now)
end

return _M
