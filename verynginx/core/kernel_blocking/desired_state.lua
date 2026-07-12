-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking desired state management.
--             Tracks what should be installed in kernel sets.
--             Promotion writes here on success; reconciliation compares
--             desired vs actual and applies drift repairs in enforce mode.

local _M = {}

local json = require "dkjson"

local DESIRED_STATE_DICT = "vn_config"
local DESIRED_STATE_PREFIX = "kb:desired:"
local INDEX_KEY = "kb:desired_index"

local function shared()
    return ngx.shared[DESIRED_STATE_DICT]
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

local function index_add(key)
    local idx = index_read()
    for _, v in ipairs(idx) do
        if v == key then return end
    end
    idx[#idx + 1] = key
    index_write(idx)
end

local function index_remove(key)
    local idx = index_read()
    local filtered = {}
    for _, v in ipairs(idx) do
        if v ~= key then
            filtered[#filtered + 1] = v
        end
    end
    index_write(filtered)
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
    s:set(key, json.encode(entry), store_ttl)
    index_add(key)
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
    local idx = index_read()
    -- Compact stale index slots once before paging.
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
        idx = compact
    end

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
    return #index_read()
end

return _M
