-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Whitelist generation management + generation-qualified cache.
--
-- Generation = { epoch, sequence }:
--   epoch    — unpredictable boot ID (random bytes), changes on each master start
--   sequence — monotonic counter within epoch, incremented on every whitelist
--               change (static add/remove, auto-whitelist create/expire)
--
-- Cache key: ip_rep:wl_cache:<epoch>:<sequence>:<canonical_ip>
-- Both positive and negative results are cached with generation qualification.
-- Old-generation caches expire via TTL; no get_keys() scan needed.

local _M = {}

local random = require "core.random"

local SHARED_DICT = "ip_reputation"
local EPOCH_KEY = "ip_rep:whitelist_epoch"
local SEQ_KEY = "ip_rep:whitelist_sequence"
local CACHE_TTL = 60  -- seconds

-- ---------------------------------------------------------------------------
-- Get the current {epoch, sequence}. Creates epoch on first call.
-- ---------------------------------------------------------------------------
function _M.get_generation()
    local s = ngx.shared[SHARED_DICT]
    if not s then return nil, nil end
    local epoch = s:get(EPOCH_KEY)
    local seq = s:get(SEQ_KEY)
    return epoch, seq and tonumber(seq) or 0
end

-- ---------------------------------------------------------------------------
-- Initialize the epoch (called once from init_by_lua / init_worker).
-- Only sets epoch if not already present (preserves across graceful reload).
-- ---------------------------------------------------------------------------
function _M.init_epoch()
    local s = ngx.shared[SHARED_DICT]
    if not s then return nil, nil end
    local existing = s:get(EPOCH_KEY)
    if existing then
        local seq = s:get(SEQ_KEY)
        return existing, seq and tonumber(seq) or 0
    end
    local epoch = random.hex(16)
    -- add() = create-if-absent; preserves epoch across graceful reload
    s:add(EPOCH_KEY, epoch, 0)  -- 0 TTL = never expire
    s:add(SEQ_KEY, 1, 0)
    return epoch, 1
end

-- ---------------------------------------------------------------------------
-- Atomically increment the sequence. Returns the new sequence number.
-- Called after a successful whitelist change (add/remove/auto).
-- ---------------------------------------------------------------------------
function _M.bump_sequence()
    local s = ngx.shared[SHARED_DICT]
    if not s then return nil end
    local new_seq = s:incr(SEQ_KEY, 1)
    return new_seq and tonumber(new_seq) or nil
end

-- ---------------------------------------------------------------------------
-- Build a generation-qualified cache key.
-- ---------------------------------------------------------------------------
function _M.cache_key(ip)
    local epoch, seq = _M.get_generation()
    if not epoch then
        -- Fallback: unqualified key (should not happen in normal operation)
        return "ip_rep:wl_cache:" .. ip
    end
    return "ip_rep:wl_cache:" .. epoch .. ":" .. tostring(seq) .. ":" .. ip
end

-- ---------------------------------------------------------------------------
-- Read from generation-qualisted cache.
-- Returns: true (whitelisted), false (not whitelisted), or nil (cache miss).
-- ---------------------------------------------------------------------------
function _M.cache_get(ip)
    local s = ngx.shared[SHARED_DICT]
    if not s then return nil end
    local key = _M.cache_key(ip)
    local val = s:get(key)
    if val == nil then return nil end
    return val == 1
end

-- ---------------------------------------------------------------------------
-- Write to generation-qualified cache.
-- @param is_whitelisted boolean
-- @param override_ttl optional TTL override (used for auto-whitelist
--        positive cache to not exceed auto-allow remaining TTL)
-- ---------------------------------------------------------------------------
function _M.cache_set(ip, is_whitelisted, ttl)
    local s = ngx.shared[SHARED_DICT]
    if not s then return end
    local key = _M.cache_key(ip)
    s:set(key, is_whitelisted and 1 or 0, ttl or CACHE_TTL)
end

-- ---------------------------------------------------------------------------
-- Invalidate all caches for a specific IP (used when whitelist changes
-- affect a specific entry). Since we use generation-qualified keys,
-- simply bumping the sequence makes old entries stale; this function
-- provides explicit invalidation for the current generation.
-- ---------------------------------------------------------------------------
function _M.cache_invalidate(ip)
    local s = ngx.shared[SHARED_DICT]
    if not s then return end
    local epoch, seq = _M.get_generation()
    if not epoch then return end
    s:delete("ip_rep:wl_cache:" .. epoch .. ":" .. tostring(seq) .. ":" .. ip)
end

return _M
