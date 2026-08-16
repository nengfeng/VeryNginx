-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking desired state management.
--             Tracks what should be installed in kernel sets.
--             Promotion writes here on success; reconciliation compares
--             desired vs actual and applies drift repairs in enforce mode.

local _M = {}

local json = require "dkjson"
local random = require "core.random"

local DESIRED_STATE_DICT = "vn_config"
local DESIRED_STATE_PREFIX = "kb:desired:"
local INDEX_KEY = "kb:desired_index"
local INDEX_LOCK_KEY = "kb:desired_index_lock"
local INDEX_LOCK_TTL = 5
local INDEX_LOCK_SLEEP = 0.002
local INDEX_LOCK_MAX_RETRIES = 500
local COMPACT_INTERVAL = 300
local _last_compact = 0

local function shared()
    return ngx.shared[DESIRED_STATE_DICT]
end

local function locks()
    return ngx.shared.vn_locks
end

-- Acquire the index lock with an unforgeable token. The token is checked on
-- release so an unlock never deletes a lock that a later holder re-acquired
-- after this one's TTL expired (mirrors ip_reputation's token pattern).
-- Returns the token on success, nil if the lock could not be acquired within
-- the retry budget.
local function index_lock()
    local l = locks()
    if not l then return nil end
    local token = random.bytes(8)
    local retries = 0
    while not l:add(INDEX_LOCK_KEY, token, INDEX_LOCK_TTL) do
        retries = retries + 1
        if retries > INDEX_LOCK_MAX_RETRIES then
            return nil
        end
        ngx.sleep(INDEX_LOCK_SLEEP)
    end
    return token
end

local function index_unlock(token)
    local l = locks()
    if not l then return end
    if l:get(INDEX_LOCK_KEY) == token then
        l:delete(INDEX_LOCK_KEY)
    end
end

local function index_read()
    local s = shared()
    if not s then return {} end
    local raw = s:get(INDEX_KEY) or "[]"
    local ok, t = pcall(json.decode, raw)
    if not ok or type(t) ~= "table" then return {} end
    return t
end

local function index_write(idx)
    local s = shared()
    if not s then return end
    s:set(INDEX_KEY, json.encode(idx), 0)
end

local function state_key(ip, family, list)
    return DESIRED_STATE_PREFIX .. family .. ":" .. list .. ":" .. ip
end

-- Add the key to the desired-state index under the index lock. The entry is
-- only discoverable by reconcile/list via this index, so a silent drop here
-- would render it invisible forever. Returns false (and logs an error) if the
-- lock could not be acquired within the retry budget so the caller can fail
-- the whole desired-state write instead of leaving an orphaned entry.
local function index_add(key)
    local token = index_lock()
    if not token then
        ngx.log(ngx.ERR, "kb: desired index lock unavailable after ",
            INDEX_LOCK_MAX_RETRIES, " retries for ", key)
        return false
    end
    local idx = index_read()
    for _, v in ipairs(idx) do
        if v == key then index_unlock(token); return true end
    end
    idx[#idx + 1] = key
    index_write(idx)
    index_unlock(token)
    return true
end

local function index_remove(key)
    local token = index_lock()
    if not token then
        -- Best effort: a missed remove only leaves a dead index entry that the
        -- next compact prunes; it never loses live data.
        return
    end
    local idx = index_read()
    local filtered = {}
    for _, v in ipairs(idx) do
        if v ~= key then
            filtered[#filtered + 1] = v
        end
    end
    index_write(filtered)
    index_unlock(token)
end

local function compact_index_if_due()
    local now = ngx.time()
    if now - _last_compact < COMPACT_INTERVAL then return end
    local token = index_lock()
    if not token then return end
    _last_compact = now

    local s = shared()
    local idx = index_read()
    local compact = {}
    local changed = false
    for _, key in ipairs(idx) do
        if s:get(key) then
            compact[#compact + 1] = key
        else
            changed = true
        end
    end
    if changed then
        index_write(compact)
    end
    index_unlock(token)
end

-- ---------------------------------------------------------------------------
-- Mark a desired entry.
-- @param ip string
-- @param family "ipv4"|"ipv6"
-- @param list "scanner_drop"|"cc_drop"|"manual_drop"
-- @param evidence table
-- @param ttl number: desired TTL in seconds (nil/0 => no absolute expiry)
-- @param extra table|nil: { source, policy, reason }
-- Returns: true on success
-- ---------------------------------------------------------------------------
function _M.set_desired(ip, family, list, evidence, ttl, extra)
    local s = shared()
    if not s or not ip or not family or not list then return false end
    extra = extra or {}
    local key = state_key(ip, family, list)
    local now = ngx.time()
    local entry = {
        ip = ip,
        family = family,
        list = list,
        evidence = evidence or {},
        ttl = ttl,
        expires_at = (ttl and ttl > 0) and (now + ttl) or nil,
        source = extra.source or "automatic",
        policy = extra.policy,
        reason = extra.reason,
        reconciliation_mode = extra.reconciliation_mode
            or (extra.source == "manual" and "manual")
            or "ensure",
        promotion_count = extra.promotion_count,
        ttl_tier = extra.ttl_tier,
        -- kept for Phase 2 test compatibility
        dry_run_state = extra.dry_run_state or "promoted",
        status = "desired",
        created_at = now,
        updated_at = now,
    }
    local store_ttl = 0
    if entry.expires_at then
        store_ttl = math.max(entry.expires_at - now, 60)
    end
    local ok_set = s:set(key, json.encode(entry), store_ttl)
    if not ok_set then
        return false, "shared dict full, entry not persisted"
    end
    local idx_ok = index_add(key)
    if not idx_ok then
        -- Entry already written but not indexed; remove it so reconcile has no
        -- dangling record, and surface the failure to the caller.
        s:delete(key)
        return false, "failed to record desired-state index entry"
    end
    return true
end

-- ---------------------------------------------------------------------------
-- Read a desired entry.
-- ---------------------------------------------------------------------------
function _M.get_desired(ip, family, list)
    local s = shared()
    if not s then return nil end
    local raw = s:get(state_key(ip, family, list))
    if not raw then return nil end
    local ok, entry = pcall(json.decode, raw)
    if not ok then return nil end
    return entry
end

-- ---------------------------------------------------------------------------
-- Remove one desired entry.
-- ---------------------------------------------------------------------------
function _M.remove_desired(ip, family, list)
    local s = shared()
    if not s or not ip or not family or not list then return false end
    local key = state_key(ip, family, list)
    s:delete(key)
    index_remove(key)
    return true
end

-- ---------------------------------------------------------------------------
-- Remove all desired drop entries for an IP (optionally one family).
-- @return number removed
-- ---------------------------------------------------------------------------
function _M.clear_for_ip(ip, family)
    if not ip then return 0 end
    local lists = { "scanner_drop", "cc_drop", "manual_drop" }
    local families = family and { family } or { "ipv4", "ipv6" }
    local removed = 0
    for _, fam in ipairs(families) do
        for _, list in ipairs(lists) do
            if _M.get_desired(ip, fam, list) then
                _M.remove_desired(ip, fam, list)
                removed = removed + 1
            end
        end
    end
    return removed
end

-- ---------------------------------------------------------------------------
-- Remove all desired entries for automatic drop lists (scanner/cc).
-- ---------------------------------------------------------------------------
function _M.clear_auto()
    local s = shared()
    if not s then return 0 end
    local token = index_lock()
    if not token then
        ngx.log(ngx.ERR, "kb: clear_auto index lock unavailable after ",
            INDEX_LOCK_MAX_RETRIES, " retries")
        return 0
    end
    local idx = index_read()
    local kept = {}
    local removed = 0
    for _, key in ipairs(idx) do
        local _, list = key:match("^" .. DESIRED_STATE_PREFIX .. "([^:]+):([^:]+):(.+)$")
        if list == "scanner_drop" or list == "cc_drop" then
            s:delete(key)
            removed = removed + 1
        else
            kept[#kept + 1] = key
        end
    end
    index_write(kept)
    index_unlock(token)
    return removed
end

-- ---------------------------------------------------------------------------
-- Paginate desired state entries.
-- ---------------------------------------------------------------------------
function _M.list_desired(cursor, page_size)
    cursor = cursor or 0
    page_size = page_size or 50
    local s = shared()
    if not s then return { entries = {}, next_cursor = nil } end
    compact_index_if_due()
    local idx = index_read()

    local entries = {}
    local i = cursor + 1
    while i <= #idx and #entries < page_size do
        local raw = s:get(idx[i])
        if raw then
            local ok, e = pcall(json.decode, raw)
            if ok and type(e) == "table" then
                entries[#entries + 1] = e
            end
        end
        i = i + 1
    end
    local next_cursor = (i <= #idx) and (i - 1) or nil
    return { entries = entries, next_cursor = next_cursor }
end

-- ---------------------------------------------------------------------------
-- Count desired entries.
-- ---------------------------------------------------------------------------
function _M.count_desired()
    compact_index_if_due()
    return #index_read()
end

-- Count desired entries for a single list (scanner_drop/cc_drop/manual_drop).
function _M.count_by_list(list)
    if not list then return 0 end
    compact_index_if_due()
    local s = shared()
    if not s then return 0 end
    local n = 0
    local prefix = DESIRED_STATE_PREFIX
    for _, key in ipairs(index_read()) do
        -- key: kb:desired:<family>:<list>:<ip>
        local _, lst = key:match("^" .. prefix .. "([^:]+):([^:]+):")
        if lst == list and s:get(key) then
            n = n + 1
        end
    end
    return n
end

return _M
