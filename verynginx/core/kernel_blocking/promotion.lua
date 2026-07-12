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
local json = require "dkjson"

local function detect_family(ip)
    if type(ip) == "string" and ip:find(":", 1, true) then
        return "ipv6"
    end
    return "ipv4"
end

-- Virtual promotion bucket (observe-only; separate from enforce bucket).
-- Key: kb:observe_bucket:state  (table with tokens, last_refill)
-- Not persisted to disk.
local OBSERVE_BUCKET_DICT = "vn_locks"
local OBSERVE_BUCKET_KEY = "kb:observe_bucket:state"

-- Enforce token bucket (consumed when actually installing to kernel).
local ENFORCE_BUCKET_DICT = "vn_locks"
local ENFORCE_BUCKET_KEY = "kb:enforce_bucket:state"

local function observe_bucket_shared()
    return ngx.shared[OBSERVE_BUCKET_DICT]
end

-- Read the virtual observe bucket state.
-- Returns a table (never nil).
local function read_bucket()
    local s = observe_bucket_shared()
    if not s then return { tokens = 0, last_refill = 0 } end
    local raw = s:get(OBSERVE_BUCKET_KEY)
    if not raw then return { tokens = 0, last_refill = 0 } end
    local ok, t = pcall(json.decode, raw)
    if not ok or type(t) ~= "table" then
        return { tokens = 0, last_refill = 0 }
    end
    return t
end

-- Read the virtual enforce bucket state (used in enforce mode).
local function read_enforce_bucket()
    local s = ngx.shared[ENFORCE_BUCKET_DICT]
    if not s then return { tokens = 0, last_refill = 0 } end
    local raw = s:get(ENFORCE_BUCKET_KEY)
    if not raw then return { tokens = 0, last_refill = 0 } end
    local ok, t = pcall(json.decode, raw)
    if not ok or type(t) ~= "table" then
        return { tokens = 0, last_refill = 0 }
    end
    return t
end

-- Refill observe-bucket tokens before evaluation round.
-- Uses promotion_rate_limit config (limit, interval, burst).
local function refill_observe_bucket()
    local kb_cfg = config.kernel_ip_blocking
    local rate_cfg = kb_cfg and kb_cfg.promotion_rate_limit
    if not rate_cfg then return end
    local now_ms = ngx.time() * 1000  -- millisecond precision
    local bucket = read_bucket()
    local burst = rate_cfg.burst or 1000
    local limit = rate_cfg.limit or 1000
    local interval = rate_cfg.interval or 60
    local tokens = bucket.tokens or 0
    local last_refill = bucket.last_refill or 0
    local elapsed_ms = now_ms - last_refill
    if elapsed_ms <= 0 then return end
    local refill = math.floor(elapsed_ms * limit / (interval * 1000))
    if refill > 0 then
        tokens = math.min(tokens + refill, burst)
        local s = observe_bucket_shared()
        if s then
            s:set(OBSERVE_BUCKET_KEY, json.encode({
                tokens = tokens, last_refill = now_ms,
            }), 3600)
        end
    end
end

-- Refill enforce-bucket tokens (consumed when installing to kernel).
-- Uses same promotion_rate_limit config.
local function refill_enforce_bucket()
    local kb_cfg = config.kernel_ip_blocking
    local rate_cfg = kb_cfg and kb_cfg.promotion_rate_limit
    if not rate_cfg then return end
    local now_ms = ngx.time() * 1000
    local bucket = read_enforce_bucket()
    local burst = rate_cfg.burst or 1000
    local limit = rate_cfg.limit or 1000
    local interval = rate_cfg.interval or 60
    local tokens = bucket.tokens or 0
    local last_refill = bucket.last_refill or 0
    local elapsed_ms = now_ms - last_refill
    if elapsed_ms <= 0 then return end
    local refill = math.floor(elapsed_ms * limit / (interval * 1000))
    if refill > 0 then
        tokens = math.min(tokens + refill, burst)
        local s = ngx.shared[ENFORCE_BUCKET_DICT]
        if s then
            s:set(ENFORCE_BUCKET_KEY, json.encode({
                tokens = tokens, last_refill = now_ms,
            }), 3600)
        end
    end
end

-- Consume one enforce token. Returns true if token was available.
local function consume_enforce_token()
    local s = ngx.shared[ENFORCE_BUCKET_DICT]
    if not s then return false end
    local bucket = read_enforce_bucket()
    if (bucket.tokens or 0) < 1 then return false end
    s:set(ENFORCE_BUCKET_KEY, json.encode({
        tokens = bucket.tokens - 1, last_refill = bucket.last_refill,
    }), 3600)
    return true
end

-- Check if this candidate would be observe-rate-limited.
-- Returns true if no token available.
local function would_observe_rate_limit()
    local rate_cfg = config.kernel_ip_blocking and
        config.kernel_ip_blocking.promotion_rate_limit
    if not rate_cfg then return false end
    local bucket = read_bucket()
    return (bucket.tokens or 0) < 1
end

-- ---------------------------------------------------------------------------
-- Security gate: returns true if IP is safe to consider for promotion.
-- @param ip string
-- @param family string: "ipv4" or "ipv6"
-- @returns bool, reason
-- ---------------------------------------------------------------------------
local function passes_security_gate(ip, family)
    local kb_cfg = config.kernel_ip_blocking
    if not kb_cfg then return false, "no_config" end

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
    if ip == "127.0.0.1" or ip == "::1" then return false, "loopback" end

    -- Whitelist check
    if ir.is_whitelisted(ip) then return false, "whitelisted" end

    -- Topology check: observe mode collects data regardless of topology;
    -- enforce mode requires topology=direct (validated at config save time).
    if kb_cfg.mode == "enforce" and kb_cfg.topology ~= "direct" then
        return false, "topology"
    end

    return true, nil
end

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
-- Updates state machine on success.
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

	-- Check if already installed in scanner_drop (same set) to avoid dups.
	-- Design §5.1 overlap: if already in cc_drop, we still proceed to
	-- upgrade to scanner_drop (atomic add + delete cc_drop).
	local existing = sm.get(ip)
	if existing and existing.state == "installed" and existing.list == "scanner_drop" then
		return true
	end
	-- Capture overlap before intermediate transitions mutate scanner state.
	local executor_cleanup = get_installed_auto_set(ip) == "cc_drop"
	local existing_cc = sm.get_policy(ip, "cc")

	-- Consume enforce token
    if not consume_enforce_token() then
        evidence_tbl.result = "rate_limited"
        sm.upsert(ip, "scanner", "rate_limited", evidence_tbl, {})
        return true
    end

	-- Compute TTL: use canary TTL on first install (shorter TTL for canary).
	-- Design §5.1 overlap: if IP already in cc_drop, preserve the longer TTL.
	local max_ttl = (kb_cfg.scanner and kb_cfg.scanner.max_ttl) or 86400
	local canary_ttl = (kb_cfg.canary and kb_cfg.canary.scanner_ttl) or 60
	local ttl = math.min(canary_ttl, max_ttl)
	if block_hits >= 10 then
		ttl = max_ttl
	end
	-- If upgrading from cc_drop, use max of existing remaining TTL and new TTL
	local ttl_source = existing_cc or existing
	if ttl_source and ttl_source.expires_at then
		local remaining = ttl_source.expires_at - ngx.time()
		if remaining and remaining > ttl then
			ttl = math.min(remaining, max_ttl)
		end
	end

    local family = detect_family(ip)
    -- Intermediate states: promoted -> dispatch_pending -> installed/degraded
    sm.upsert(ip, "scanner", "promoted", evidence_tbl, {
        list = "scanner_drop",
        family = family,
    })
    sm.transition(ip, "scanner", "dispatch_pending", {
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
	evidence_tbl.result = "promoted"
	desired.set_desired(ip, family, "scanner_drop", evidence_tbl, ttl, {
		source = "automatic",
		policy = "scanner",
		reason = "auto_promotion",
		reconciliation_mode = "ensure",
	})
	-- scanner supersedes cc desired entry
	desired.remove_desired(ip, family, "cc_drop")
	sm.upsert(ip, "scanner", "installed", evidence_tbl, {
		list = "scanner_drop",
		family = family,
		installed_at = ngx.time(),
		expires_at = ngx.time() + ttl,
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
		" installed into scanner_drop (ttl=", ttl, "s)")
	return true
end

-- ---------------------------------------------------------------------------
-- Evaluate SCANNER candidates.
-- Reads scanner evidence from shared dict, evaluates loose/strict thresholds.
-- In observe mode: only logs "would_*" results.
-- In enforce mode: actually installs passing candidates via executor.
-- ---------------------------------------------------------------------------
local function evaluate_scanner_candidates()
    local candidates = sm.list_candidates(0, 100)

    for _, c in ipairs(candidates.entries) do
        if c.policy ~= "scanner" then goto continue end
        local ip = c.ip

        -- Skip already-installed entries (idempotent re-evaluation)
        local existing_scanner = sm.get_policy(ip, "scanner")
        if existing_scanner and existing_scanner.state == "installed" then
            goto continue
        end

        -- Security gate
        local gate_ok, reason = passes_security_gate(ip, "ipv4")
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

        -- Observe: check rate limit
        local rate_limited = would_observe_rate_limit()

        local mode = config.kernel_ip_blocking.mode

        local ev = {
            strict = strict, loose = loose,
            block_hits = block_hits, flagged = flagged,
        }

        if mode == "enforce" then
            -- Enforce mode: actually install
            if strict and not rate_limited then
                enforce_promote_scanner(ip, block_hits, flagged)
            elseif strict and rate_limited then
                ev.result = "would_rate_limit"
                sm.upsert(ip, "scanner", "candidate", ev, {})
            else
                ev.result = "would_not_promote"
                sm.upsert(ip, "scanner", "candidate", ev, {})
            end
        else
            -- Observe mode (default): log only
            if strict and not rate_limited then
                ev.result = "would_promote"
                sm.upsert(ip, "scanner", "candidate", ev, {})
            elseif strict and rate_limited then
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
-- Consumes a token and calls executor.add() to install into cc_drop.
-- Design §6.4: cc_drop with short TTL, progressive.
-- ---------------------------------------------------------------------------
local function enforce_promote_cc(ip, violation_count)
	local kb_cfg = config.kernel_ip_blocking

	-- Emergency pause: stop installing but keep observing
	if kb_cfg.emergency_pause then
		sm.upsert(ip, "cc", "candidate",
			{ result = "paused", violation_count = violation_count }, {})
		return true
	end

	-- Check overlap: if already in scanner_drop, no need for cc_drop
	local existing_set = get_installed_auto_set(ip)
	if existing_set == "scanner_drop" then
		sm.upsert(ip, "cc", "candidate",
			{ result = "already_in_scanner_drop", violation_count = violation_count }, {})
		return true
	end

	-- Already installed in cc_drop: skip
	if existing_set == "cc_drop" then
		return true
	end

	-- Consume enforce token
	if not consume_enforce_token() then
		sm.upsert(ip, "cc", "rate_limited",
			{ violation_count = violation_count }, {})
		return true
	end

	-- Compute TTL: use cc.ttl (short, Design §5.1: 1-10 min)
	local ttl = (kb_cfg.cc and kb_cfg.cc.ttl) or 300
	local max_ttl = (kb_cfg.cc and kb_cfg.cc.max_ttl) or 1800
	-- Progressive TTL: more violations = longer TTL, up to max_ttl
	ttl = math.min(ttl + (violation_count - 1) * 60, max_ttl)

	local family = detect_family(ip)
	local ev_tbl = { violation_count = violation_count }
	sm.upsert(ip, "cc", "promoted", ev_tbl, {
		list = "cc_drop",
		family = family,
	})
	sm.transition(ip, "cc", "dispatch_pending", {
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
	ev_tbl.result = "promoted"
	desired.set_desired(ip, family, "cc_drop", ev_tbl, ttl, {
		source = "automatic",
		policy = "cc",
		reason = "auto_promotion",
		reconciliation_mode = "ensure",
	})
	sm.upsert(ip, "cc", "installed", ev_tbl, {
		list = "cc_drop",
		family = family,
		installed_at = ngx.time(),
		expires_at = ngx.time() + ttl,
	})

	ngx.log(ngx.WARN, "kernel_blocking: IP ", ip,
		" installed into cc_drop (ttl=", ttl, "s, violations=", violation_count, ")")
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

    for _, c in ipairs(candidates.entries) do
        if c.policy ~= "cc" then goto continue end
        local ip = c.ip

        -- Skip already-installed CC entries (idempotent re-evaluation)
        local existing_cc = sm.get_policy(ip, "cc")
        if existing_cc and existing_cc.state == "installed" then
            goto continue
        end

        -- Also skip if already in scanner_drop (higher priority)
        local existing_scanner = sm.get_policy(ip, "scanner")
        if existing_scanner and existing_scanner.state == "installed" and existing_scanner.list == "scanner_drop" then
            sm.upsert(ip, "cc", "candidate",
                { result = "already_in_scanner_drop" }, {})
            goto continue
        end

        -- Security gate
        local gate_ok, reason = passes_security_gate(ip, "ipv4")
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

		local mode = kb_cfg.mode
		local rate_limited = would_observe_rate_limit()

		if cc_enforce and violations >= min_windows and not rate_limited then
			enforce_promote_cc(ip, violations)
		elseif cc_enforce and violations >= min_windows and rate_limited then
			sm.upsert(ip, "cc", "candidate",
				{ violation_count = violations, result = "would_rate_limit" }, {})
		else
			local result_str = "would_not_promote"
			if mode ~= "enforce" then
				result_str = (cc_enforce and "cc_observe") or "cc_observe_only"
			end
			sm.upsert(ip, "cc", "candidate",
				{ violation_count = violations, result = result_str }, {})
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
    local life_ok, life = pcall(require, "core.kernel_blocking.lifecycle")
    if life_ok and life and life.evidence_allowed then
        local allowed = life.evidence_allowed("scanner", now or ngx.time())
        if not allowed then
            -- still evaluate for observe logging after cutoff only
        end
    end
    -- Refill observe-bucket tokens before evaluation round
    refill_observe_bucket()
    -- In enforce mode, also refill the enforce bucket
    if config.kernel_ip_blocking.mode == "enforce" then
        refill_enforce_bucket()
    end
    _M.evaluate(now)
end

return _M
