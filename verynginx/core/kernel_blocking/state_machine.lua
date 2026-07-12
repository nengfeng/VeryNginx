-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking state machine for Phase 1 (observe-only).
--             States: observed → candidate → (evaluating) → rejected
--             In Phase 1, we only track the state for read/display; no
--             transitions are persisted to disk.

local _M = {}

local json = require "dkjson"

-- Per-IP candidate entry stored in shared dict (bounded candidate index).
-- Key:   kb:candidate:<ip>
-- Value: JSON { ip, state, policy, evidence, updated_at }
local CANDIDATE_DICT = "vn_config"
local CANDIDATE_KEY_PREFIX = "kb:candidate:"
local INDEX_KEY = "kb:candidate_index"
local INDEX_TTL = 7 * 86400  -- 7-day TTL on candidate entries
local MAX_CANDIDATES = 10000  -- bounded index size

local function shared()
    return ngx.shared[CANDIDATE_DICT]
end

-- ---------------------------------------------------------------------------
-- Upsert a candidate entry.
-- @param ip string
-- @param policy string: "scanner" or "cc"
-- @param state string: STATES value
-- @param evidence table: e.g., { score, hard_block_hits, ... }
-- ---------------------------------------------------------------------------
function _M.upsert_candidate(ip, policy, state, evidence)
    local s = shared()
    if not s then return false end
    local entry = {
        ip = ip,
        policy = policy,
        state = state,
        evidence = evidence or {},
        updated_at = ngx.time(),
    }
    local key = CANDIDATE_KEY_PREFIX .. ip
    s:set(key, json.encode(entry), INDEX_TTL)
    -- Add to index (append-only; dedup on next read)
    local idx_raw = s:get(INDEX_KEY) or "[]"
    local ok, idx = pcall(json.decode, idx_raw)
    if not ok or type(idx) ~= "table" then idx = {} end
    -- Only add if not already present
    local found = false
    for _, v in ipairs(idx) do
        if v == ip then found = true; break end
    end
    if not found and #idx < MAX_CANDIDATES then
        idx[#idx + 1] = ip
        s:set(INDEX_KEY, json.encode(idx), INDEX_TTL)
    end
    return true
end

-- ---------------------------------------------------------------------------
-- Read a candidate entry by IP.
-- ---------------------------------------------------------------------------
function _M.get_candidate(ip)
    local s = shared()
    if not s then return nil end
    local raw = s:get(CANDIDATE_KEY_PREFIX .. ip)
    if not raw then return nil end
    return json.decode(raw)
end

-- ---------------------------------------------------------------------------
-- List all candidates (paginated via cursor for bounded read).
-- Uses the INDEX_KEY index; does NOT call get_keys(0).
-- @param cursor number: 0-based start index into the index array
-- @param page_size number: max entries per page
-- @return table: { entries = {...}, next_cursor = number|nil }
function _M.list_candidates(cursor, page_size)
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
        local entry = _M.get_candidate(idx[i])
        if entry then
            entries[#entries + 1] = entry
        end
        i = i + 1
    end
    local next_cursor
    if i <= #idx then
        next_cursor = i - 1
    end
    return { entries = entries, next_cursor = next_cursor }
end

-- ---------------------------------------------------------------------------
-- Count current candidates.
-- ---------------------------------------------------------------------------
function _M.count_candidates()
    local s = shared()
    if not s then return 0 end
    local idx_raw = s:get(INDEX_KEY) or "[]"
    local ok, idx = pcall(json.decode, idx_raw)
    if not ok or type(idx) ~= "table" then return 0 end
    return #idx
end

return _M
