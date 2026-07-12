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
--             Candidate entries stored in shared dict (bounded candidate
--             index). Persistence is handled by the desired_state module.

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

-- Per-IP entry stored in shared dict (bounded index).
-- Key:   kb:candidate:<ip>
-- Value: JSON { ip, state, policy, list, evidence, installed_at,
--               expires_at, source, updated_at }
local CANDIDATE_DICT = "vn_config"
local CANDIDATE_KEY_PREFIX = "kb:candidate:"
local INDEX_KEY = "kb:candidate_index"
local INDEX_TTL = 7 * 86400  -- 7-day TTL on candidate entries
local MAX_CANDIDATES = 10000  -- bounded index size

local function shared()
    return ngx.shared[CANDIDATE_DICT]
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
        updated_at = ngx.time(),
    }
    local key = CANDIDATE_KEY_PREFIX .. ip
    local ttl = extra.expires_at and math.max(extra.expires_at - ngx.time(), 60)
        or INDEX_TTL
    s:set(key, json.encode(entry), ttl)
    -- Add to index (append-only; dedup on next read)
    local idx_raw = s:get(INDEX_KEY) or "[]"
    local ok, idx = pcall(json.decode, idx_raw)
    if not ok or type(idx) ~= "table" then idx = {} end
    local found = false
    for _, v in ipairs(idx) do if v == ip then found = true; break end end
    if not found and #idx < MAX_CANDIDATES then
        idx[#idx + 1] = ip
        s:set(INDEX_KEY, json.encode(idx), INDEX_TTL)
    end
    return true
end

-- ---------------------------------------------------------------------------
-- Read an entry by IP.
-- ---------------------------------------------------------------------------
function _M.get(ip)
    local s = shared()
    if not s then return nil end
    local raw = s:get(CANDIDATE_KEY_PREFIX .. ip)
    if not raw then return nil end
    return json.decode(raw)
end

-- ---------------------------------------------------------------------------
-- Update state of an existing entry (shorthand for transitions).
-- @param ip string
-- @param new_state string: STATE value
-- @param extra table: optional extra fields to merge
-- ---------------------------------------------------------------------------
function _M.transition(ip, new_state, extra)
    local entry = _M.get(ip)
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
    local key = CANDIDATE_KEY_PREFIX .. ip
    local ttl = entry.expires_at and math.max(entry.expires_at - ngx.time(), 60)
        or INDEX_TTL
    s:set(key, json.encode(entry), ttl)
    return true
end

-- ---------------------------------------------------------------------------
-- Remove an entry entirely.
-- ---------------------------------------------------------------------------
function _M.remove(ip)
    local s = shared()
    if not s then return end
    s:delete(CANDIDATE_KEY_PREFIX .. ip)
    local idx_raw = s:get(INDEX_KEY) or "[]"
    local ok, idx = pcall(json.decode, idx_raw)
    if not ok or type(idx) ~= "table" then return end
    local filtered = {}
    for _, v in ipairs(idx) do if v ~= ip then filtered[#filtered + 1] = v end end
    s:set(INDEX_KEY, json.encode(filtered), INDEX_TTL)
end

-- ---------------------------------------------------------------------------
-- List all entries (paginated via bounded index; no get_keys()).
-- @param cursor number: 0-based start index into the index array
-- @param page_size number: max entries per page
-- @param state_filter string|nil: optional state filter
-- @return table: { entries = {...}, next_cursor = number|nil }
-- ---------------------------------------------------------------------------
function _M.list(cursor, page_size, state_filter)
    cursor = cursor or 0
    page_size = page_size or 50
    local s = shared()
    if not s then return { entries = {}, next_cursor = nil } end
    local idx_raw = s:get(INDEX_KEY) or "[]"
    local ok, idx = pcall(json.decode, idx_raw)
    if not ok or type(idx) ~= "table" then
        return { entries = {}, next_cursor = nil }
    end
    local entries = {}
    local i = cursor + 1
    while i <= #idx and #entries < page_size do
        local entry = _M.get(idx[i])
        if entry then
            if not state_filter or entry.state == state_filter then
                entries[#entries + 1] = entry
            end
        end
        i = i + 1
    end
    local next_cursor = (i <= #idx) and (i - 1) or nil
    return { entries = entries, next_cursor = next_cursor }
end

-- ---------------------------------------------------------------------------
-- Count entries (optionally filtered by state).
-- ---------------------------------------------------------------------------
function _M.count(state_filter)
    local s = shared()
    if not s then return 0 end
    local idx_raw = s:get(INDEX_KEY) or "[]"
    local ok, idx = pcall(json.decode, idx_raw)
    if not ok or type(idx) ~= "table" then return 0 end
    if not state_filter then return #idx end
    local n = 0
    for _, ip in ipairs(idx) do
        local e = _M.get(ip)
        if e and e.state == state_filter then n = n + 1 end
    end
    return n
end

-- ---------------------------------------------------------------------------
-- Health-check-driven transitions.
-- When Helper connection is lost, installed entries transition to
-- scope_validation_pending. Once connection is restored (and entries
-- verified still present), they transition back to installed.
-- ---------------------------------------------------------------------------
function _M.to_scope_validation_pending(ip)
    return _M.transition(ip, STATE.scope_validation_pending, {
        reason = "helper_unreachable",
    })
end

function _M.from_scope_validation_pending(ip, verified)
    if verified then
        return _M.transition(ip, STATE.installed, {
            reason = "helper_restored",
        })
    else
        return _M.transition(ip, STATE.degraded, {
            reason = "helper_restored_entry_missing",
        })
    end
end

-- Backward-compatible aliases (Phase 1 API surface)
_M.upsert_candidate = _M.upsert
_M.get_candidate = _M.get
_M.list_candidates = _M.list
_M.count_candidates = _M.count

return _M
