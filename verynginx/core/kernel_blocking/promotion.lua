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
local config = require "core.config"
local json = require "dkjson"

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

    -- Check if already installed to avoid duplicate adds
    local existing = sm.get(ip)
    if existing and existing.state == "installed" then
        return true
    end

    -- Consume enforce token
    if not consume_enforce_token() then
        evidence_tbl.result = "rate_limited"
        sm.upsert(ip, "scanner", "rate_limited", evidence_tbl, {})
        return true
    end

    -- Compute TTL: use canary TTL on first install (shorter TTL for canary)
    local max_ttl = (kb_cfg.scanner and kb_cfg.scanner.max_ttl) or 86400
    local canary_ttl = (kb_cfg.canary and kb_cfg.canary.scanner_ttl) or 60
    local ttl = math.min(canary_ttl, max_ttl)
    if block_hits >= 10 then
        ttl = max_ttl
    end

    -- Install via executor
    local executor = require "core.kernel_blocking.executor"
    local exec = executor.get_executor()
    local call_ok, add_ok, add_err = pcall(function()
        return exec.add("scanner_drop", "ipv4", ip, ttl)
    end)

    if not call_ok then
        ngx.log(ngx.ERR, "kernel_blocking: executor.add crashed for ", ip, ": ",
            tostring(add_ok))
        evidence_tbl.result = "executor_error"
        evidence_tbl.error = tostring(add_ok)
        sm.upsert(ip, "scanner", "degraded", evidence_tbl, {})
        return false
    end

    if not add_ok then
        ngx.log(ngx.ERR, "kernel_blocking: executor.add returned false for ",
            ip, ": ", tostring(add_err))
        evidence_tbl.result = "executor_error"
        evidence_tbl.error = tostring(add_err)
        sm.upsert(ip, "scanner", "degraded", evidence_tbl, {})
        return false
    end

    -- Success: transition state machine
    evidence_tbl.result = "promoted"
    sm.upsert(ip, "scanner", "installed", evidence_tbl, {
        list = "scanner_drop",
        installed_at = ngx.time(),
        expires_at = ngx.time() + ttl,
    })

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

        -- Security gate
        local gate_ok, reason = passes_security_gate(ip, "ipv4")
        if not gate_ok then
            sm.upsert(ip, "scanner", "rejected", { reason = reason }, {})
            goto continue
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
-- Main evaluate function (worker 0 callback entry point).
-- Already called within the kernel_blocking-enabled gate.
-- ---------------------------------------------------------------------------
function _M.evaluate(_now)
    -- Phase 1: scanner-only evaluation (CC requires warm-up)
    local kb_cfg = config.kernel_ip_blocking
    if not kb_cfg then return end

    if kb_cfg.scanner and kb_cfg.scanner.enabled then
        evaluate_scanner_candidates()
    end
    -- CC evaluation deferred to Phase 1 post warm-up (see plan §6.4)
end

-- ---------------------------------------------------------------------------
-- Module init: exports for worker 0 timer wiring in core.init.
-- ---------------------------------------------------------------------------
function _M.process_candidates(now)
    if not (config.kernel_ip_blocking and config.kernel_ip_blocking.enabled) then
        return
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
