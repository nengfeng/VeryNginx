-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-13
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking promotion token bucket (Design §6.2).
--
-- Two independent buckets:
--   observe  — virtual bucket for observability (no token consumption)
--   enforce  — actual bucket consumed when installing to kernel
--
-- Uses microunits (1 token = 1,000,000 µu) to avoid floating-point
-- differences between Lua and Helper implementations.
--
-- State structure (stored in vn_locks shared dict):
--   {
--     version = 1,
--     tokens_microunits = 0,
--     last_refill_ms = 1783728000000,
--     limit = 1000,
--     interval = 60,
--     burst = 1000
--   }
--
-- Hot-reload: when limit/burst/interval change, refill using old params
-- first, then install new params and clamp balance to new burst.

local _M = {}

local json = require "dkjson"

local DICT = "vn_locks"
local MICROUNITS_PER_TOKEN = 1000000

local OBSERVE_KEY = "kb:promotion_bucket:v1:observe:state"
local ENFORCE_KEY = "kb:promotion_bucket:v1:enforce:state"

local function shared()
    return ngx.shared[DICT]
end

local function now_ms()
    return ngx.time() * 1000
end

-- Read bucket state, returning a normalized table (never nil).
local function read_state(key)
    local s = shared()
    if not s then
        return { version = 1, tokens_microunits = 0, last_refill_ms = now_ms(), limit = 0, interval = 60, burst = 0 }
    end
    local raw = s:get(key)
    if not raw then
        return { version = 1, tokens_microunits = 0, last_refill_ms = now_ms(), limit = 0, interval = 60, burst = 0 }
    end
    local ok, t = pcall(json.decode, raw)
    if not ok or type(t) ~= "table" then
        return { version = 1, tokens_microunits = 0, last_refill_ms = now_ms(), limit = 0, interval = 60, burst = 0 }
    end
    return t
end

local function write_state(key, state)
    local s = shared()
    if not s then return end
    s:set(key, json.encode(state), 0)
end

-- Get rate config from current kernel_ip_blocking config.
local function rate_config()
    local config = require "core.config"
    local kb_cfg = config.kernel_ip_blocking
    if not kb_cfg then return nil end
    local cfg = kb_cfg.promotion_rate_limit
    if not cfg then return nil end
    return {
        limit = cfg.limit or 1000,
        interval = cfg.interval or 60,
        burst = cfg.burst or 1000,
    }
end

-- Refill a bucket based on elapsed time and current rate config.
-- Returns the updated state (not yet written).
local function refill(state, cfg, now)
    now = now or now_ms()
    cfg = cfg or rate_config()
    if not cfg or cfg.limit <= 0 then return state end

    local last = state.last_refill_ms or now
    local elapsed = now - last
    if elapsed <= 0 then return state end

    -- Microunits refill: elapsed_ms * limit * MICROUNITS_PER_TOKEN / (interval * 1000)
    local refill_uu = math.floor(elapsed * cfg.limit * MICROUNITS_PER_TOKEN / (cfg.interval * 1000))
    local tokens = (state.tokens_microunits or 0) + refill_uu
    local max_uu = cfg.burst * MICROUNITS_PER_TOKEN
    if tokens > max_uu then tokens = max_uu end

    return {
        version = 1,
        tokens_microunits = tokens,
        last_refill_ms = now,
        limit = cfg.limit,
        interval = cfg.interval,
        burst = cfg.burst,
    }
end

-- Detect config change and perform hot-reload transition.
-- If rate params changed, refill with old params first, then clamp to new burst.
local function maybe_reload(state, cfg, now)
    if not cfg then return state end
    -- No change in params: just refill.
    if state.limit == cfg.limit and state.interval == cfg.interval and state.burst == cfg.burst then
        return refill(state, cfg, now)
    end
    -- Params changed: refill using OLD params up to now, then clamp to new burst.
    local old_cfg = {
        limit = state.limit or cfg.limit,
        interval = state.interval or cfg.interval,
        burst = state.burst or cfg.burst,
    }
    local refilled = refill(state, old_cfg, now)
    local new_max_uu = cfg.burst * MICROUNITS_PER_TOKEN
    if refilled.tokens_microunits > new_max_uu then
        refilled.tokens_microunits = new_max_uu
    end
    refilled.limit = cfg.limit
    refilled.interval = cfg.interval
    refilled.burst = cfg.burst
    return refilled
end

-- ---------------------------------------------------------------------------
-- Observe bucket (virtual — for observability only).
-- ---------------------------------------------------------------------------

function _M.refill_observe()
    local cfg = rate_config()
    if not cfg then return end
    local state = read_state(OBSERVE_KEY)
    local updated = maybe_reload(state, cfg)
    write_state(OBSERVE_KEY, updated)
end

-- Check if observe bucket has at least 1 token (for would_rate_limit reporting).
function _M.observe_has_token()
    local cfg = rate_config()
    if not cfg then return true end
    local state = read_state(OBSERVE_KEY)
    local updated = maybe_reload(state, cfg)
    write_state(OBSERVE_KEY, updated)
    return updated.tokens_microunits >= MICROUNITS_PER_TOKEN
end

-- ---------------------------------------------------------------------------
-- Enforce bucket (consumed when installing to kernel).
-- ---------------------------------------------------------------------------

function _M.refill_enforce()
    local cfg = rate_config()
    if not cfg then return end
    local state = read_state(ENFORCE_KEY)
    local updated = maybe_reload(state, cfg)
    write_state(ENFORCE_KEY, updated)
end

-- Consume one enforce token. Returns true if available and consumed.
function _M.consume_enforce()
    local cfg = rate_config()
    if not cfg then return false end
    local state = read_state(ENFORCE_KEY)
    local updated = maybe_reload(state, cfg)
    if updated.tokens_microunits < MICROUNITS_PER_TOKEN then
        write_state(ENFORCE_KEY, updated)
        return false
    end
    updated.tokens_microunits = updated.tokens_microunits - MICROUNITS_PER_TOKEN
    write_state(ENFORCE_KEY, updated)
    return true
end

-- Check enforce bucket availability without consuming.
function _M.enforce_has_token()
    local cfg = rate_config()
    if not cfg then return true end
    local state = read_state(ENFORCE_KEY)
    local updated = maybe_reload(state, cfg)
    write_state(ENFORCE_KEY, updated)
    return updated.tokens_microunits >= MICROUNITS_PER_TOKEN
end

-- ---------------------------------------------------------------------------
-- Status / observability.
-- ---------------------------------------------------------------------------

function _M.observe_status()
    local cfg = rate_config()
    local state = read_state(OBSERVE_KEY)
    local updated = maybe_reload(state, cfg, now_ms())
    return {
        tokens = math.floor((updated.tokens_microunits or 0) / MICROUNITS_PER_TOKEN),
        tokens_microunits = updated.tokens_microunits or 0,
        limit = updated.limit or (cfg and cfg.limit) or 0,
        interval = updated.interval or (cfg and cfg.interval) or 60,
        burst = updated.burst or (cfg and cfg.burst) or 0,
        last_refill_ms = updated.last_refill_ms or 0,
    }
end

function _M.enforce_status()
    local cfg = rate_config()
    local state = read_state(ENFORCE_KEY)
    local updated = maybe_reload(state, cfg, now_ms())
    return {
        tokens = math.floor((updated.tokens_microunits or 0) / MICROUNITS_PER_TOKEN),
        tokens_microunits = updated.tokens_microunits or 0,
        limit = updated.limit or (cfg and cfg.limit) or 0,
        interval = updated.interval or (cfg and cfg.interval) or 60,
        burst = updated.burst or (cfg and cfg.burst) or 0,
        last_refill_ms = updated.last_refill_ms or 0,
    }
end

-- Reset both buckets (e.g., on disable transition).
function _M.reset_buckets()
    local s = shared()
    if not s then return end
    local now = now_ms()
    local cfg = rate_config()
    local empty = {
        version = 1, tokens_microunits = 0, last_refill_ms = now,
        limit = cfg and cfg.limit or 1000,
        interval = cfg and cfg.interval or 60,
        burst = cfg and cfg.burst or 1000,
    }
    s:set(OBSERVE_KEY, json.encode(empty), 0)
    s:set(ENFORCE_KEY, json.encode(empty), 0)
end

return _M
