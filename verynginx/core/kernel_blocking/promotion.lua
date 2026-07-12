-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking Promotion Policy (Phase 1: observe-only).
--
-- Runs as a worker 0 periodic callback. Consumes evidence from
-- shared-dict counters and evaluates loose/strict thresholds.
-- In observe mode, only logs would_promote/would_rate_limit/rejected
-- results; does NOT create desired states or send IPC.

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

-- ---------------------------------------------------------------------------
-- Evaluate SCANNER candidates (Phase 1: observe only).
-- Reads scanner evidence from shared dict, evaluates loose/strict thresholds.
-- Updates the state machine with results.
-- ---------------------------------------------------------------------------
local function evaluate_scanner_candidates()
    local candidates = sm.list_candidates(0, 100)

    for _, c in ipairs(candidates.entries) do
        if c.policy ~= "scanner" then goto continue end
        local ip = c.ip

        -- Security gate
        local gate_ok, reason = passes_security_gate(ip, "ipv4")
        if not gate_ok then
            sm.upsert_candidate(ip, "scanner", "rejected",
                { reason = reason })
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

        -- Update state machine (observe: log only)
        if strict and not rate_limited then
            sm.upsert_candidate(ip, "scanner", "candidate", {
                strict = true, loose = loose,
                block_hits = block_hits, flagged = flagged,
                result = "would_promote",
            })
            -- Optionally consume observe token (rate-limit the metrics)
            -- consume_observe_token()
        elseif strict and rate_limited then
            sm.upsert_candidate(ip, "scanner", "candidate", {
                strict = true, loose = loose,
                block_hits = block_hits, flagged = flagged,
                result = "would_rate_limit",
            })
        else
            sm.upsert_candidate(ip, "scanner", "candidate", {
                strict = false, loose = loose,
                block_hits = block_hits, flagged = flagged,
                result = "would_not_promote",
            })
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
    _M.evaluate(now)
end

return _M
