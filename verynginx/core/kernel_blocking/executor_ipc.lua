-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking executor via IPC Protocol v1.
--             Wraps ipc_client to provide the same interface as
--             executor_mock. Attaches Protected Scope Binding fields
--             (Design §8.3.4) to DROP-mutating operations.

local _M = {}

local client = require "core.kernel_blocking.ipc_client"
local scope_binding = require "core.kernel_blocking.scope_binding"

local function err_code(err)
    if type(err) == "string" and err ~= "" then
        return err
    end
    return "unknown_error"
end

local function is_scope_err(code)
    return code == "scope_validation_pending"
        or code == "scope_digest_mismatch"
        or code == "scope_unvalidated"
        or code == "helper_instance_changed"
        or code == "table_generation_changed"
        or code == "activation_generation_changed"
        or code == "local_address_changed"
        or (type(code) == "string" and code:find("address_not_local", 1, true) == 1)
end

-- ---------------------------------------------------------------------------
-- probe() -> capabilities
-- ---------------------------------------------------------------------------
function _M.probe()
    local resp = client.request_safe("probe", "automatic", {})
    return resp.result or {
        protocol_min = 1, protocol_max = 1,
        capabilities = {}, version = "unknown",
    }
end

-- ---------------------------------------------------------------------------
-- ensure_base(config) -> ok, error?
-- ---------------------------------------------------------------------------
function _M.ensure_base(config)
    local payload = scope_binding.ensure_base_payload(config)
    local resp, err = client.request("ensure_base", "automatic", payload)
    if not resp then
        scope_binding.invalidate(err_code(err))
        return false, err_code(err)
    end
    if resp.ok then
        scope_binding.mark_validated(resp.result or {}, payload.scope_digest, payload.activation_generation)
        return true, nil
    end
    local code = err_code((resp.error and resp.error) or "ensure_base_failed")
    if type(resp.error) == "string" then code = resp.error end
    scope_binding.invalidate(code)
    return false, code
end

-- ---------------------------------------------------------------------------
-- add(set, family, ip, ttl) -> ok, error?
-- ---------------------------------------------------------------------------
function _M.add(set, family, ip, ttl)
    local allowed, why = scope_binding.drop_writes_allowed()
    if not allowed then
        return false, why or "scope_validation_pending"
    end
    local resp, err = client.request("add", "automatic", {
        items = {
            { set = set, family = family, ip = ip, ttl = ttl,
              source = "automatic", reason = "auto_promotion" },
        },
        binding = scope_binding.binding_fields(),
    })
    if not resp then
        local code = err_code(err)
        if is_scope_err(code) then
            scope_binding.invalidate(code)
        end
        return false, code
    end
    if resp.ok then
        return true, nil
    end
    local code = type(resp.error) == "string" and resp.error or "add_failed"
    if is_scope_err(code) then
        scope_binding.invalidate(code)
    end
    return false, code
end

-- ---------------------------------------------------------------------------
-- delete(set, family, ip) -> ok, error?
-- ---------------------------------------------------------------------------
function _M.delete(set, family, ip)
    local resp, err = client.request_safe("delete", "automatic", {
        items = { { set = set, family = family, ip = ip } },
    })
    if resp and resp.ok then
        return true, nil
    end
    return false, err or "delete_failed"
end

-- ---------------------------------------------------------------------------
-- contains(set, family, ip) -> bool, error?
-- ---------------------------------------------------------------------------
function _M.contains(set, family, ip)
    local page = _M.list(set, family, 0)
    for _, entry in ipairs(page.entries or {}) do
        if entry.ip == ip then return true, nil end
    end
    return false, nil
end

-- ---------------------------------------------------------------------------
-- list(set, family, cursor) -> { entries = {...}, next_cursor = n|nil }
-- ---------------------------------------------------------------------------
function _M.list(set, family, cursor)
    local resp = client.request_safe("list", "automatic", {
        set = set, family = family, cursor = cursor or 0,
    })
    return resp.result or { entries = {}, next_cursor = nil }
end

-- ---------------------------------------------------------------------------
-- replace_allow_snapshot(entries) -> ok, error?
-- ---------------------------------------------------------------------------
function _M.replace_allow_snapshot(entries)
    local resp, err = client.request_safe("replace_allow_snapshot", "whitelist", {
        items = entries or {},
    })
    if resp and resp.ok then
        return true, nil
    end
    return false, err or "replace_allow_snapshot_failed"
end

-- ---------------------------------------------------------------------------
-- reconcile(desired_snapshot) -> { added, updated, removed, failed }
-- ---------------------------------------------------------------------------
function _M.reconcile(snapshot)
    local allowed, why = scope_binding.drop_writes_allowed()
    if not allowed then
        return {
            added = 0, updated = 0, removed = 0, preserved = 0, failed = 0,
            error = why or "scope_validation_pending",
        }
    end
    local resp, err = client.request("reconcile", "reconcile", {
        snapshot = snapshot or {},
        binding = scope_binding.binding_fields(),
    })
    if not resp then
        local code = err_code(err)
        if is_scope_err(code) then
            scope_binding.invalidate(code)
        end
        return {
            added = 0, updated = 0, removed = 0, preserved = 0, failed = 0,
            error = code,
        }
    end
    local r = resp.result or {}
    return {
        added = r.added or 0,
        updated = r.updated or 0,
        removed = r.removed or 0,
        preserved = r.preserved or 0,
        failed = r.failed or 0,
    }
end

-- ---------------------------------------------------------------------------
-- flush_owned(scope) -> { removed = n }
-- ---------------------------------------------------------------------------
function _M.flush_owned(scope)
    local resp = client.request_safe("flush_owned", "automatic", { scope = scope or "all" })
    return resp.result or { removed = 0 }
end

-- ---------------------------------------------------------------------------
-- health() -> status table
-- ---------------------------------------------------------------------------
function _M.health()
    local resp = client.request_safe("health", "automatic", {})
    local h = resp.result or { state = "degraded", instance_id = "unknown" }
    -- Side-effect: validate binding against health snapshot.
    if h.state == "ok" then
        local ok, reason = scope_binding.validate_health(h)
        if not ok then
            h.scope_validation = reason or "scope_unvalidated"
        else
            h.scope_validation = "ok"
        end
    end
    return h
end

return _M
