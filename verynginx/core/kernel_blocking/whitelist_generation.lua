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
--
-- The epoch is stable across graceful reloads (init_epoch preserves it via
-- add()), so it is cached worker-locally: only the sequence (which changes on
-- every whitelist mutation) still requires a shared read per call. This trims
-- two shared reads per cache_key() on the hot is_whitelisted() path.
-- ---------------------------------------------------------------------------
local _epoch_cache = nil  -- worker-local copy; refreshed by init_epoch

function _M.get_generation()
    local s = ngx.shared[SHARED_DICT]
    if not s then return nil, nil end
    local epoch = _epoch_cache
    if epoch == nil then
        epoch = s:get(EPOCH_KEY)
        _epoch_cache = epoch
    end
    local seq = s:get(SEQ_KEY)
    return epoch, seq and tonumber(seq) or 0
end

-- Internal: get generation using worker-local epoch cache + one shared read for seq.
-- Used by is_whitelisted to read generation once per request.
function _M._get_generation()
    local s = ngx.shared[SHARED_DICT]
    if not s then return nil, nil end
    local epoch = _epoch_cache
    if epoch == nil then
        epoch = s:get(EPOCH_KEY)
        _epoch_cache = epoch
    else
        -- Verify cached epoch still exists in store (handles test mocks that reset the store)
        local stored_epoch = s:get(EPOCH_KEY)
        if stored_epoch ~= epoch then
            epoch = stored_epoch
            _epoch_cache = epoch
        end
    end
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
        _epoch_cache = existing
        local seq = s:get(SEQ_KEY)
        return existing, seq and tonumber(seq) or 0
    end
    local epoch = random.hex(16)
    -- add() = create-if-absent; preserves epoch across graceful reload
    s:add(EPOCH_KEY, epoch, 0)  -- 0 TTL = never expire
    s:add(SEQ_KEY, 1, 0)
    _epoch_cache = epoch
    return epoch, 1
end

-- ---------------------------------------------------------------------------
-- Atomically increment the sequence. Returns the new sequence number.
-- Called after a successful whitelist change (add/remove/auto).
-- Triggers async snapshot push to Helper via ngx.timer.at.
-- ---------------------------------------------------------------------------
function _M.bump_sequence()
    local s = ngx.shared[SHARED_DICT]
    if not s then return nil end
    local new_seq = s:incr(SEQ_KEY, 1)
    new_seq = new_seq and tonumber(new_seq) or nil
    -- Async push (ngx.timer.at runs in a request-like context with
    -- access to modules and shared dicts; does not block the caller).
    -- Guard: ngx.timer may not exist in test/non-OpenResty contexts.
    if new_seq and ngx.timer and ngx.timer.at then
        local ok, err = ngx.timer.at(0, function()
            _M.push_allow_snapshot()
        end)
        if not ok then
            ngx.log(ngx.WARN, "kernel_blocking: timer for snapshot push failed: ", err)
        end
    end
    return new_seq
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

-- Internal: build cache key from pre-read generation (avoids extra shared read).
function _M._cache_key_with_gen(ip, epoch, seq)
    if not epoch then
        return "ip_rep:wl_cache:" .. ip
    end
    return "ip_rep:wl_cache:" .. epoch .. ":" .. tostring(seq) .. ":" .. ip
end

-- ---------------------------------------------------------------------------
-- Read from generation-qualified cache.
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

-- Internal: cache_get with pre-read generation.
function _M._cache_get_with_gen(s, ip, epoch, seq)
    local key = _M._cache_key_with_gen(ip, epoch, seq)
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

-- Internal: cache_set with pre-read generation.
function _M._cache_set_with_gen(s, ip, is_whitelisted, epoch, seq, ttl)
    local key = _M._cache_key_with_gen(ip, epoch, seq)
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

-- ---------------------------------------------------------------------------
-- Build the full allow list (static + auto-whitelist) and push it to the
-- Helper via executor.replace_allow_snapshot.
-- Called asynchronously (ngx.timer.at) after bump_sequence().
-- ---------------------------------------------------------------------------
function _M.push_allow_snapshot()
    local executor = require "core.kernel_blocking.executor"
    local exec = executor.get_executor()
    local config = require "core.config"
    local json = require "dkjson"

    local entries = {}

    -- Static whitelist from config (ip_reputation.whitelist)
    local ip_rep = config and config.ip_reputation
    local static_wl = ip_rep and ip_rep.whitelist or {}
    for _, entry in ipairs(static_wl) do
        -- entry may be a bare IP or CIDR string (e.g. "10.0.0.0/8")
        -- Keep the full entry (with prefix) for nftables interval set
        local family = entry:find(":") and "ipv6" or "ipv4"
        entries[#entries + 1] = { ip = entry, family = family }
    end

    -- Auto-whitelist from shared dict (ip_rep:awl:* with index)
    local s = ngx.shared[SHARED_DICT]
    if s then
        local awl_idx_raw = s:get("ip_rep:awl_index") or "[]"
        local ok, awl_idx = pcall(json.decode, awl_idx_raw)
        if ok and type(awl_idx) == "table" then
            for _, ip in ipairs(awl_idx) do
                if s:get("ip_rep:awl:" .. ip) then
                    local family = ip:find(":") and "ipv6" or "ipv4"
                    entries[#entries + 1] = { ip = ip, family = family }
                end
            end
        end
    end

    local ok, err = exec.replace_allow_snapshot(entries)
    if not ok then
        ngx.log(ngx.WARN, "kernel_blocking: push_allow_snapshot failed: ", err)
    end
end

return _M
