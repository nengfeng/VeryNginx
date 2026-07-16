-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Mock Nft Executor for Phase 2 testing.
--             All state stored in a shared dict (vn_config).
--             Supports all 8 contract methods for dry-run reconciliation.

local _M = {}

local json = require "dkjson"
local contract = require "core.kernel_blocking.executor_contract"

local MOCK_DICT = "vn_config"
local DATA_PREFIX = "kb_mock:nft:"
local INDEX_KEY = "kb_mock:nft_index"

local function shared()
    return ngx.shared[MOCK_DICT]
end

local function set_key(set, family, ip)
    return DATA_PREFIX .. set .. ":" .. family .. ":" .. ip
end

local function index_read()
    local s = shared()
    if not s then return {} end
    local raw = s:get(INDEX_KEY) or "{}"
    local ok, t = pcall(json.decode, raw)
    if not ok or type(t) ~= "table" then return {} end
    return t
end

local function index_write(index)
    local s = shared()
    if not s then return end
    s:set(INDEX_KEY, json.encode(index), 0)
end

-- ---------------------------------------------------------------------------
-- probe() -> capabilities table
-- ---------------------------------------------------------------------------
function _M.probe()
    return {
        protocol_min = 1,
        protocol_max = 1,
        capabilities = {
            inet_family = true,
            interval_set = true,
            timeout_element = true,
            atomic_transaction = true,
        },
        version = "mock-0.1.0",
    }
end

-- ---------------------------------------------------------------------------
-- ensure_base(config) -> ok, error?
-- ---------------------------------------------------------------------------
function _M.ensure_base(config)
    local ok, sb = pcall(require, "core.kernel_blocking.scope_binding")
    if ok and sb then
        local payload = sb.ensure_base_payload(config)
        sb.mark_validated({
            helper_instance_id = "mock",
            instance_id = "mock",
            scope_digest = payload.scope_digest,
            table_generation = 1,
            local_address_digest = "mock-local",
            activation_generation = payload.activation_generation,
        }, payload.scope_digest, payload.activation_generation)
    end
    return true, nil
end

function _M.rebind_scope(config)
    return _M.ensure_base(config)
end

-- ---------------------------------------------------------------------------
-- add(set, family, ip, ttl) -> ok, error?
-- ---------------------------------------------------------------------------
function _M.add(set, family, ip, ttl)
    local ok, sb = pcall(require, "core.kernel_blocking.scope_binding")
    if ok and sb then
        local allowed, _ = sb.drop_writes_allowed()
        if not allowed then
            -- Auto-bootstrap mock binding for unit tests that skip ensure_base.
            local payload = sb.ensure_base_payload()
            sb.mark_validated({
                helper_instance_id = "mock",
                instance_id = "mock",
                scope_digest = payload.scope_digest,
                table_generation = 1,
                local_address_digest = "mock-local",
            }, payload.scope_digest, payload.activation_generation)
            local allowed2, why2 = sb.drop_writes_allowed()
            if not allowed2 then
                return false, why2 or "scope_validation_pending"
            end
        end
    end
    if not set or not ip or not family then
        return false, contract.ERRORS.invalid_address
    end
    local s = shared()
    if not s then return false, contract.ERRORS.unavailable end
    local key = set_key(set, family, ip)
    local entry = json.encode({
        ip = ip, family = family, set = set,
        expires_at = ttl and (ngx.time() + ttl) or nil,
        created_at = ngx.time(),
    })
    s:set(key, entry, ttl or 0)
    -- Add to index
    local idx = index_read()
    idx[key] = true
    index_write(idx)
    return true, nil
end

-- ---------------------------------------------------------------------------
-- delete(set, family, ip) -> ok, error?
-- ---------------------------------------------------------------------------
function _M.delete(set, family, ip)
    if not set or not ip or not family then
        return false, contract.ERRORS.invalid_address
    end
    local s = shared()
    if not s then return false, contract.ERRORS.unavailable end
    local key = set_key(set, family, ip)
    s:delete(key)
    local idx = index_read()
    idx[key] = nil
    index_write(idx)
    return true, nil
end

-- ---------------------------------------------------------------------------
-- contains(set, family, ip) -> bool, error?
-- ---------------------------------------------------------------------------
function _M.contains(set, family, ip)
    local s = shared()
    if not s then return false, contract.ERRORS.unavailable end
    local key = set_key(set, family, ip)
    return s:get(key) ~= nil, nil
end

-- ---------------------------------------------------------------------------
-- list(set, family, cursor) -> { entries = {...}, next_cursor = n|nil }
-- ---------------------------------------------------------------------------
function _M.list(set, family, cursor)
    cursor = cursor or 0
    local page_size = 1000
    local s = shared()
    if not s then return { entries = {}, next_cursor = nil } end
    local idx = index_read()
    local keys = {}
    for k, _ in pairs(idx) do
        -- Filter by set and family
        local pattern = DATA_PREFIX .. set .. ":" .. family .. ":"
        if k:sub(1, #pattern) == pattern then
            keys[#keys + 1] = k
        end
    end
    table.sort(keys)
    local entries = {}
    local i = cursor + 1
    while i <= #keys and #entries < page_size do
        local raw = s:get(keys[i])
        if raw then
            local ok, entry = pcall(json.decode, raw)
            if ok then
                entries[#entries + 1] = entry
            end
        end
        i = i + 1
    end
    local next_cursor = (i <= #keys) and (i - 1) or nil
    return { entries = entries, next_cursor = next_cursor }
end

-- ---------------------------------------------------------------------------
-- replace_allow_snapshot(entries) -> ok, error?
-- entries: { { ip = ..., family = "ipv4"|"ipv6" }, ... }
-- Replaces the entire atom-helper-managed allow set with the given entries.
-- ---------------------------------------------------------------------------
function _M.replace_allow_snapshot(entries)
    local s = shared()
    if not s then return false, contract.ERRORS.unavailable end
    -- Clear old allow entries from mock nft
    local idx = index_read()
    local to_clear = {}
    for key, _ in pairs(idx) do
        if key:find(DATA_PREFIX .. "allow:", 1, true) == 1 then
            to_clear[#to_clear + 1] = key
        end
    end
    for _, key in ipairs(to_clear) do
        s:delete(key)
        idx[key] = nil
    end
    -- Add new allow entries
    for _, entry in ipairs(entries or {}) do
        local key = set_key("allow", entry.family or "ipv4", entry.ip)
        s:set(key, json.encode({
            ip = entry.ip, family = entry.family or "ipv4",
            set = "allow", created_at = ngx.time(),
        }), 0)
        idx[key] = true
    end
    index_write(idx)
    return true, nil
end

-- ---------------------------------------------------------------------------
-- reconcile(desired_snapshot) -> { added, updated, removed, preserved, failed }
-- desired_snapshot: { [set_family_ip] = { ip, family, set, expires_at, mode } }
-- mode: "ensure" | "preserve_only" | "manual"
-- ---------------------------------------------------------------------------
function _M.reconcile(snapshot)
    local result = { added = 0, updated = 0, removed = 0, preserved = 0, failed = 0 }
    if not snapshot then return result end
    -- Read current state
    local idx = index_read()
    local desired_keys = {}
    for key, _ in pairs(snapshot) do
        desired_keys[key] = true
    end
    -- Add/update entries from snapshot.
    -- Snapshot from desired_state uses expires_at (absolute), but add()
    -- expects ttl (relative). Convert with floor of 1s to match
    -- reconciliation.remaining_ttl and avoid negative/zero TTLs on
    -- clock-skew or already-expired entries.
    local now = ngx.time()
    for key, entry in pairs(snapshot) do
        local s, f, ip = entry.set, entry.family, entry.ip
        local ttl = entry.ttl or (entry.expires_at and math.max(entry.expires_at - now, 1)) or 0
        local key_in_idx = idx[key] or false
        local ok, _ = _M.add(s, f, ip, ttl)
        if ok then
            if key_in_idx then
                result.updated = result.updated + 1
            else
                result.added = result.added + 1
            end
        else
            result.failed = result.failed + 1
        end
    end
    -- Remove entries not in snapshot
    for key, _ in pairs(idx) do
        if not desired_keys[key] then
            local set, family, ip = key:match(DATA_PREFIX .. "(.+):(.+):(.+)")
            if set and family and ip then
                _M.delete(set, family, ip)  -- order matches delete(set, family, ip)
                result.removed = result.removed + 1
            end
        end
    end
    return result
end

-- ---------------------------------------------------------------------------
-- chunked_reconcile(chunk) -> { added, updated, removed, preserved, failed }, scope_err?
-- chunk: { snapshot_id, chunk_index, final_chunk, desired, remove, ... }
-- Design §8.3.3: remove only applied on final_chunk.
-- ---------------------------------------------------------------------------
function _M.chunked_reconcile(chunk)
    local result = { added = 0, updated = 0, removed = 0, preserved = 0, failed = 0 }
    if not chunk then return result end

    local idx = index_read()

    -- Apply desired entries (add/update).
    for _, entry in ipairs(chunk.desired or {}) do
        local s, f, ip = entry.set or entry.list, entry.family, entry.ip
        if s and f and ip then
            local key = set_key(s, f, ip)
            local key_in_idx = idx[key] or false
            local ttl = entry.ttl or (entry.expires_at and (entry.expires_at - ngx.time())) or 0
            local ok, _ = _M.add(s, f, ip, ttl)
            if ok then
                if key_in_idx then
                    result.updated = result.updated + 1
                else
                    result.added = result.added + 1
                end
            else
                result.failed = result.failed + 1
            end
        end
    end

    -- Apply remove operations only on final chunk.
    if chunk.final_chunk then
        for _, r in ipairs(chunk.remove or {}) do
            local s, f, ip = r.set or r.list, r.family, r.ip
            if s and f and ip then
                local ok, _ = _M.delete(s, f, ip)
                if ok then
                    result.removed = result.removed + 1
                else
                    result.failed = result.failed + 1
                end
            end
        end
    end

    return result
end

-- ---------------------------------------------------------------------------
-- flush_owned(scope) -> { removed = n }
-- scope: "auto" | "all" | "detach"
-- ---------------------------------------------------------------------------
function _M.flush_owned(scope)
    local idx = index_read()
    local count = 0
    local auto_sets = { scanner_drop = true, cc_drop = true }
    local new_idx = {}
    for key, _ in pairs(idx) do
        local sname = key:match(DATA_PREFIX .. "([^:]+):([^:]+):(.+)")
        local should_remove = (scope == "all" or scope == "detach")
            or (scope == "auto" and auto_sets[sname])
        if should_remove then
            local s = shared()
            if s then s:delete(key) end
            count = count + 1
        else
            new_idx[key] = true
        end
    end
    index_write(new_idx)
    return { removed = count }
end

-- ---------------------------------------------------------------------------
-- health() -> status table
-- ---------------------------------------------------------------------------
function _M.health()
    local ok, sb = pcall(require, "core.kernel_blocking.scope_binding")
    local binding = ok and sb and sb.get_binding() or {}
    return {
        state = "ok",
        instance_id = binding.helper_instance_id or "mock",
        helper_instance_id = binding.helper_instance_id or "mock",
        table_generation = binding.table_generation or 1,
        scope_digest = binding.scope_digest,
        local_address_digest = binding.local_address_digest or "mock-local",
        set_count = 0,
        scope_validation = binding.validated and "ok" or (binding.reason or "scope_unvalidated"),
    }
end

return _M
