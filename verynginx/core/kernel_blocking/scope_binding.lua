-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-13
-- @Author  : VeryNginx v2
-- @Disc    : Protected Scope Binding (Design §8.3.4).
--             Computes canonical scope_digest, tracks Helper session binding,
--             and gates DROP mutating operations until ensure_base succeeds.

local _M = {}

local json = require "dkjson"
local config = require "core.config"

local LOCKS = "vn_locks"
local BINDING_KEY = "kb:scope_binding:v1"

local function locks()
    return ngx.shared[LOCKS]
end

local function to_hex(bin)
    if not bin then return "" end
    local t = {}
    for i = 1, #bin do
        t[i] = string.format("%02x", string.byte(bin, i))
    end
    return table.concat(t)
end

-- Prefer resty.sha256; fall back to ngx.md5 with explicit prefix.
local function digest_hex(s)
    local ok_sha, dig = pcall(function()
        local sha_mod = require "resty.sha256"
        local h = sha_mod:new()
        if not h then error("sha256_new_failed") end
        if not h:update(s) then error("sha256_update_failed") end
        local final = h:final()
        if not final then error("sha256_final_failed") end
        return to_hex(final)
    end)
    if ok_sha and type(dig) == "string" and dig ~= "" then
        return dig
    end
    if ngx.md5 then
        return "md5:" .. ngx.md5(s)
    end
    return "len:" .. tostring(#s)
end

local function sorted_copy(arr)
    local out = {}
    if type(arr) ~= "table" then return out end
    for _, v in ipairs(arr) do out[#out + 1] = tostring(v) end
    table.sort(out)
    return out
end

-- Canonical scope payload used for digest (Design §8.3.4).
function _M.canonical_scope(kb)
    kb = kb or config.kernel_ip_blocking or {}
    return {
        scope = kb.scope or "web",
        protected_addresses = sorted_copy(kb.protected_addresses),
        protected_ports = sorted_copy(kb.protected_ports),
        ipv4_enabled = not kb.ipv4 or kb.ipv4.enabled ~= false,
        ipv6_enabled = kb.ipv6 and kb.ipv6.enabled == true or false,
    }
end

function _M.compute_scope_digest(kb)
    local canon = _M.canonical_scope(kb)
    -- Stable JSON-ish encoding without depending on key order of objects:
    -- fixed field order + already-sorted arrays.
    local parts = {
        "scope=" .. tostring(canon.scope),
        "addrs=" .. table.concat(canon.protected_addresses, ","),
        "ports=" .. table.concat(canon.protected_ports, ","),
        "ipv4=" .. (canon.ipv4_enabled and "1" or "0"),
        "ipv6=" .. (canon.ipv6_enabled and "1" or "0"),
    }
    return digest_hex(table.concat(parts, "\n"))
end

function _M.get_binding()
    local s = locks()
    if not s then
        return {
            validated = false,
            reason = "no_shared",
            helper_instance_id = nil,
            scope_digest = nil,
            table_generation = nil,
            activation_generation = nil,
            connection_generation = 0,
        }
    end
    local raw = s:get(BINDING_KEY)
    if not raw then
        return {
            validated = false,
            reason = "unbound",
            helper_instance_id = nil,
            scope_digest = nil,
            table_generation = nil,
            activation_generation = nil,
            connection_generation = 0,
        }
    end
    local ok, t = pcall(json.decode, raw)
    if not ok or type(t) ~= "table" then
        return { validated = false, reason = "corrupt", connection_generation = 0 }
    end
    return t
end

function _M.set_binding(binding)
    local s = locks()
    if not s or type(binding) ~= "table" then return false end
    binding.updated_at = ngx.time()
    s:set(BINDING_KEY, json.encode(binding), 0)
    return true
end

function _M.invalidate(reason)
    local b = _M.get_binding()
    b.validated = false
    b.reason = reason or "invalidated"
    b.invalidated_at = ngx.time()
    -- keep last known ids for diagnostics
    _M.set_binding(b)
    return b
end

-- Called when IPC reconnects / connection dies.
function _M.on_ipc_disconnect()
    local b = _M.get_binding()
    b.connection_generation = (b.connection_generation or 0) + 1
    b.validated = false
    b.reason = "ipc_reconnect"
    b.invalidated_at = ngx.time()
    _M.set_binding(b)
    return b
end

function _M.current_activation_generation()
    local ok, life = pcall(require, "core.kernel_blocking.lifecycle")
    if ok and life and life.get_state then
        local st = life.get_state()
        return st.global_activation_generation or 1
    end
    return 1
end

-- Build ensure_base payload including binding fields.
function _M.ensure_base_payload(kb)
    kb = kb or config.kernel_ip_blocking or {}
    local digest = _M.compute_scope_digest(kb)
    return {
        scope = kb.scope or "web",
        protected_addresses = sorted_copy(kb.protected_addresses),
        protected_ports = sorted_copy(kb.protected_ports),
        ipv4 = { enabled = not kb.ipv4 or kb.ipv4.enabled ~= false },
        ipv6 = { enabled = kb.ipv6 and kb.ipv6.enabled == true or false },
        scope_digest = digest,
        activation_generation = _M.current_activation_generation(),
        client_binding = _M.get_binding(),
    }
end

-- Apply successful ensure_base / health observation.
function _M.mark_validated(helper_result, local_digest, activation_generation)
    helper_result = helper_result or {}
    local b = _M.get_binding()
    b.validated = true
    b.reason = nil
    b.helper_instance_id = helper_result.helper_instance_id or helper_result.instance_id
    b.scope_digest = helper_result.scope_digest or local_digest
    b.table_generation = helper_result.table_generation
    b.local_address_digest = helper_result.local_address_digest
    b.activation_generation = activation_generation or _M.current_activation_generation()
    b.validated_at = ngx.time()
    _M.set_binding(b)
    return b
end

-- Compare health() against local binding; invalidate on mismatch.
-- Returns: ok, reason
function _M.validate_health(health)
    health = health or {}
    local b = _M.get_binding()
    local kb = config.kernel_ip_blocking or {}
    local local_digest = _M.compute_scope_digest(kb)
    local act = _M.current_activation_generation()

    if not b.validated then
        return false, b.reason or "scope_unvalidated"
    end

    local hid = health.helper_instance_id or health.instance_id
    if b.helper_instance_id and hid and b.helper_instance_id ~= hid then
        _M.invalidate("helper_instance_changed")
        return false, "helper_instance_changed"
    end
    if health.scope_digest and b.scope_digest and health.scope_digest ~= b.scope_digest then
        _M.invalidate("scope_digest_mismatch")
        return false, "scope_digest_mismatch"
    end
    if local_digest and b.scope_digest and local_digest ~= b.scope_digest then
        _M.invalidate("scope_digest_mismatch")
        return false, "scope_digest_mismatch"
    end
    if health.table_generation and b.table_generation
        and tonumber(health.table_generation) ~= tonumber(b.table_generation) then
        _M.invalidate("table_generation_changed")
        return false, "table_generation_changed"
    end
    if b.activation_generation and act and tonumber(b.activation_generation) ~= tonumber(act) then
        _M.invalidate("activation_generation_changed")
        return false, "activation_generation_changed"
    end
    if health.local_address_digest and b.local_address_digest
        and health.local_address_digest ~= b.local_address_digest then
        _M.invalidate("local_address_changed")
        return false, "local_address_changed"
    end
    return true, nil
end

-- DROP add/renew/reconcile-add allowed only when binding is validated.
function _M.drop_writes_allowed()
    local b = _M.get_binding()
    if not b.validated then
        return false, b.reason or "scope_unvalidated"
    end
    -- Also re-check local digest vs stored.
    local local_digest = _M.compute_scope_digest()
    if b.scope_digest and local_digest ~= b.scope_digest then
        _M.invalidate("scope_digest_mismatch")
        return false, "scope_digest_mismatch"
    end
    local act = _M.current_activation_generation()
    if b.activation_generation and tonumber(b.activation_generation) ~= tonumber(act) then
        _M.invalidate("activation_generation_changed")
        return false, "activation_generation_changed"
    end
    return true, nil
end

-- Binding fields attached to mutating DROP requests.
function _M.binding_fields()
    local b = _M.get_binding()
    return {
        helper_instance_id = b.helper_instance_id,
        scope_digest = b.scope_digest or _M.compute_scope_digest(),
        table_generation = b.table_generation,
        activation_generation = b.activation_generation or _M.current_activation_generation(),
        connection_generation = b.connection_generation or 0,
    }
end

function _M.status_view()
    local b = _M.get_binding()
    local local_digest = _M.compute_scope_digest()
    return {
        validated = b.validated and true or false,
        reason = b.reason,
        helper_instance_id = b.helper_instance_id,
        scope_digest = b.scope_digest,
        local_scope_digest = local_digest,
        table_generation = b.table_generation,
        activation_generation = b.activation_generation,
        connection_generation = b.connection_generation or 0,
        local_address_digest = b.local_address_digest,
        validated_at = b.validated_at,
        invalidated_at = b.invalidated_at,
    }
end

return _M
