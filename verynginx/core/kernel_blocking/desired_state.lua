-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking desired state management (Phase 2: dry-run).
--             Tracks what _should_ be installed in kernel sets without
--             actually sending IPC to a helper. Persisted to shared dict
--             (vn_config) with versioned payload.

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

-- ---------------------------------------------------------------------------
-- Mark a desired entry for dry-run.
-- @param ip string
-- @param family "ipv4"|"ipv6"
-- @param list "scanner_drop"|"cc_drop"|"manual_drop"
-- @param evidence table
-- @param ttl number: desired TTL in seconds
-- Returns: true on success
-- ---------------------------------------------------------------------------
function _M.set_desired(ip, family, list, evidence, ttl)
    local s = shared()
    if not s then return false end
    local key = state_key(ip, family, list)
    local entry = {
        ip = ip, family = family, list = list,
        evidence = evidence or {},
        ttl = ttl,
        expires_at = ttl and (ngx.time() + ttl) or nil,
        source = "automatic",
        dry_run_state = "promoted",
        created_at = ngx.time(),
    }
    s:set(key, json.encode(entry), ttl or 86400)
    local idx = index_read()
    -- Add to index if not present
    local found = false
    for _, v in ipairs(idx) do if v == key then found = true; break end end
    if not found then idx[#idx + 1] = key; index_write(idx) end
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
    return json.decode(raw)
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
    local entries = {}
    local i = cursor + 1
    while i <= #idx and #entries < page_size do
        local raw = s:get(idx[i])
        if raw then
            local ok, e = pcall(json.decode, raw)
            if ok then entries[#entries + 1] = e end
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
