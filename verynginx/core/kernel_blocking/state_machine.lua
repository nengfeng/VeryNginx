-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking state machine (Design §5.3).
--             Full lifecycle states:
--               observed → candidate → rejected
--                                   → rate_limited → candidate
--                                   → promoted → dispatch_pending
--                                                         → degraded → reconcile
--                                                         → installed
--                                                               ├─ TTL → expired
--                                                               ├─ cleared
--                                                               ├─ whitelist → cleared
--                                                               └─ drift → degraded
--
--             Composite key support: entries are keyed by (ip, policy)
--             to allow scanner and cc to coexist for the same IP.
--             Design §5.1: scanner_drop > cc_drop.

local _M = {}

local json = require "dkjson"

-- Full lifecycle states (Design §5.3)
local STATE = {
    observed = "observed",
    candidate = "candidate",
    rejected = "rejected",
    rate_limited = "rate_limited",
    promoted = "promoted",
    dispatch_pending = "dispatch_pending",
    installed = "installed",
    expired = "expired",
    cleared = "cleared",
    degraded = "degraded",
    scope_validation_pending = "scope_validation_pending",
}

_M.STATE = STATE

-- Per-(ip, policy) entry stored in shared dict (bounded index).
-- Key:   kb:candidate:<ip>:<policy>
-- Value: JSON { ip, policy, state, list, evidence, installed_at,
--               expires_at, source, updated_at }
local CANDIDATE_DICT = "vn_config"
local CANDIDATE_KEY_PREFIX = "kb:candidate:"
local INDEX_KEY = "kb:candidate_index"
local INDEX_TTL = 7 * 86400  -- 7-day TTL on candidate entries
local MAX_CANDIDATES = 10000  -- bounded index size
local COMPACT_INTERVAL = 300  -- seconds between index compactions

local _last_compact = 0

local function compact_index()
    local s = shared()
    if not s then return end
    local now = ngx.time()
    if now - _last_compact < COMPACT_INTERVAL then return end
    _last_compact = now
    local idx_raw = s:get(INDEX_KEY) or "[]"
    local ok, idx = pcall(json.decode, idx_raw)
    if not ok or type(idx) ~= "table" then return end
    local kept = {}
    for _, composite in ipairs(idx) do
        local ip, policy = composite:match("^(.+):([^:]+)$")
        if ip and policy then
            local raw = s:get(entry_key(ip, policy))
            if raw then
                kept[#kept + 1] = composite
            end
        end
    end
    if #kept < #idx then
        s:set(INDEX_KEY, json.encode(kept), INDEX_TTL)
    end
end

local function shared()
    return ngx.shared[CANDIDATE_DICT]
end

-- Build composite key from IP and policy.
local function entry_key(ip, policy)
    return CANDIDATE_KEY_PREFIX .. ip .. ":" .. policy
end

-- ---------------------------------------------------------------------------
-- Upsert a candidate/desired-state entry.
-- @param ip string
-- @param policy string: "scanner" | "cc" | "manual"
-- @param state string: STATE value
-- @param evidence table: { score, hard_block_hits, ... }
-- @param extra table: optional extra fields (list, installed_at,
--        expires_at, source, generation, ...)
-- ---------------------------------------------------------------------------
function _M.upsert(ip, policy, state, evidence, extra)
    local s = shared()
    if not s then return false end
    extra = extra or {}
    local entry = {
        ip = ip,
        policy = policy,
        state = state,
        evidence = evidence or {},
        list = extra.list,
        installed_at = extra.installed_at,
        expires_at = extra.expires_at,
        source = extra.source or "automatic",
        generation = extra.generation,
        promotion_count = extra.promotion_count,
        ttl_tier = extra.ttl_tier,
        updated_at = ngx.time(),
    }
    local key = entry_key(ip, policy)
    local ttl = extra.expires_at and math.max(extra.expires_at - ngx.time(), 60)
        or INDEX_TTL
    s:set(key, json.encode(entry), ttl)
    -- Add to index (append-only; dedup on next read)
    local idx_raw = s:get(INDEX_KEY) or "[]"
    local ok, idx = pcall(json.decode, idx_raw)
    if not ok or type(idx) ~= "table" then idx = {} end
    local idx_key = ip .. ":" .. policy
    local found = false
    for _, v in ipairs(idx) do if v == idx_key then found = true; break end end
    if not found and #idx < MAX_CANDIDATES then
        idx[#idx + 1] = idx_key
        s:set(INDEX_KEY, json.encode(idx), INDEX_TTL)
    end
    return true
end

-- ---------------------------------------------------------------------------
-- Read an entry by IP and policy.
-- If policy is nil, returns the highest-priority installed entry for the IP
-- (scanner_drop > cc_drop > manual_drop), or the first entry found.
-- ---------------------------------------------------------------------------
function _M.get(ip, policy)
    local s = shared()
    if not s then return nil end
    if policy then
        local raw = s:get(entry_key(ip, policy))
        if not raw then return nil end
        return json.decode(raw)
    end
    -- No policy specified: find highest-priority installed entry
    for _, p in ipairs({ "scanner", "cc", "manual" }) do
        local raw = s:get(entry_key(ip, p))
        if raw then
            local entry = json.decode(raw)
            if entry and entry.state == "installed" then
                return entry
            end
        end
    end
    -- Fallback: return any entry for this IP
    for _, p in ipairs({ "scanner", "cc", "manual" }) do
        local raw = s:get(entry_key(ip, p))
        if raw then
            return json.decode(raw)
        end
    end
    return nil
end

-- ---------------------------------------------------------------------------
-- Get a specific policy entry for an IP.
-- ---------------------------------------------------------------------------
function _M.get_policy(ip, policy)
    local s = shared()
    if not s then return nil end
    local raw = s:get(entry_key(ip, policy))
    if not raw then return nil end
    return json.decode(raw)
end

-- ---------------------------------------------------------------------------
-- Update state of an existing entry (shorthand for transitions).
-- @param ip string
-- @param policy string
-- @param new_state string: STATE value
-- @param extra table: optional extra fields to merge
-- ---------------------------------------------------------------------------
function _M.transition(ip, policy, new_state, extra)
    local entry = _M.get_policy(ip, policy)
    if not entry then return false end
    entry.state = new_state
    entry.updated_at = ngx.time()
    if extra then
        for k, v in pairs(extra) do
            if v ~= nil then entry[k] = v end
        end
    end
    local s = shared()
    if not s then return false end
    local key = entry_key(ip, policy)
    local ttl = entry.expires_at and math.max(entry.expires_at - ngx.time(), 60)
        or INDEX_TTL
    s:set(key, json.encode(entry), ttl)
    return true
end

-- ---------------------------------------------------------------------------
-- Remove an entry entirely.
-- ---------------------------------------------------------------------------
function _M.remove(ip, policy)
    local s = shared()
    if not s then return end
    s:delete(entry_key(ip, policy))
    local idx_key = ip .. ":" .. policy
    local idx_raw = s:get(INDEX_KEY) or "[]"
    local ok, idx = pcall(json.decode, idx_raw)
    if not ok or type(idx) ~= "table" then return end
    local filtered = {}
    for _, v in ipairs(idx) do if v ~= idx_key then filtered[#filtered + 1] = v end end
    s:set(INDEX_KEY, json.encode(filtered), INDEX_TTL)
end

-- ---------------------------------------------------------------------------
-- List all entries (paginated via bounded index; no get_keys()).
-- @param cursor number: 0-based start index into the index array
-- @param page_size number: max entries per page
-- @param state_filter string|nil: optional state filter
-- @param policy_filter string|nil: optional policy filter
-- @return table: { entries = {...}, next_cursor = number|nil }
-- ---------------------------------------------------------------------------
function _M.list(cursor, page_size, state_filter, policy_filter)
    cursor = cursor or 0
    page_size = page_size or 50
    local s = shared()
    if not s then return { entries = {}, next_cursor = nil } end
    compact_index()
    local idx_raw = s:get(INDEX_KEY) or "[]"
    local ok, idx = pcall(json.decode, idx_raw)
    if not ok or type(idx) ~= "table" then
        return { entries = {}, next_cursor = nil }
    end
    local entries = {}
    local i = cursor + 1
    while i <= #idx and #entries < page_size do
        local composite = idx[i]
        local ip, policy = composite:match("^(.+):([^:]+)$")
        if ip and policy then
            if not policy_filter or policy == policy_filter then
                local entry = _M.get_policy(ip, policy)
                if entry then
                    if not state_filter or entry.state == state_filter then
                        entries[#entries + 1] = entry
                    end
                end
            end
        end
        i = i + 1
    end
    local next_cursor = (i <= #idx) and (i - 1) or nil
    return { entries = entries, next_cursor = next_cursor }
end

-- ---------------------------------------------------------------------------
-- List candidates (convenience wrapper with policy filter).
-- Kept for backward compatibility.
-- ---------------------------------------------------------------------------
function _M.list_candidates(cursor, page_size, state_filter)
    return _M.list(cursor, page_size, state_filter, nil)
end

-- ---------------------------------------------------------------------------
-- Count entries (optionally filtered by state and/or policy).
-- ---------------------------------------------------------------------------
function _M.count(state_filter, policy_filter)
    local s = shared()
    if not s then return 0 end
    local idx_raw = s:get(INDEX_KEY) or "[]"
    local ok, idx = pcall(json.decode, idx_raw)
    if not ok or type(idx) ~= "table" then return 0 end
    if not state_filter and not policy_filter then return #idx end
    local n = 0
    for _, composite in ipairs(idx) do
        local ip, policy = composite:match("^(.+):([^:]+)$")
        if ip and policy then
            if not policy_filter or policy == policy_filter then
                local e = _M.get_policy(ip, policy)
                if e and (not state_filter or e.state == state_filter) then
                    n = n + 1
                end
            end
        end
    end
    return n
end

-- ---------------------------------------------------------------------------
-- Health-check-driven scope_validation_pending transitions.
-- When Helper connection is lost, installed entries transition to
-- scope_validation_pending. Once connection is restored (and entries
-- verified still present), they transition back to installed.
-- ---------------------------------------------------------------------------
function _M.to_scope_validation_pending(ip, policy)
    return _M.transition(ip, policy, STATE.scope_validation_pending, {
        reason = "helper_unreachable",
    })
end

function _M.from_scope_validation_pending(ip, policy, verified)
    if verified then
        return _M.transition(ip, policy, STATE.installed, {
            reason = "helper_restored",
        })
    else
        return _M.transition(ip, policy, STATE.degraded, {
            reason = "helper_restored_entry_missing",
        })
    end
end

-- Backward-compatible aliases (Phase 1 API surface)
_M.upsert_candidate = _M.upsert
_M.get_candidate = _M.get
_M.count_candidates = _M.count
_M.list_candidates = _M.list

return _M
