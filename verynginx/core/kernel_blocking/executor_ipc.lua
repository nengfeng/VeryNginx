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
local config = require "core.config"

local rebind_inflight = false

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
        or code == "ipc_reconnect"
        or (type(code) == "string" and code:find("address_not_local", 1, true) == 1)
end

-- Re-run ensure_base + allow snapshot after reconnect / binding loss.
-- Design §8.3.4 / §10.4: DROP writes require a validated session.
function _M.rebind_scope(cfg)
    if rebind_inflight then
        return false, "scope_rebind_busy"
    end
    rebind_inflight = true
    local ok, err
    local call_ok, a, b = pcall(function()
        return _M.ensure_base(cfg or config.kernel_ip_blocking)
    end)
    if call_ok then
        ok, err = a, b
    else
        ok, err = false, tostring(a)
    end
    if ok then
        local ok_wlg, err_wlg = pcall(function()
            local wlg = require "core.kernel_blocking.whitelist_generation"
            if wlg.push_allow_snapshot then
                wlg.push_allow_snapshot()
            end
        end)
        if not ok_wlg then
            ngx.log(ngx.WARN, "kernel_blocking: push_allow_snapshot after rebind failed: ", tostring(err_wlg))
        end
    else
        ngx.log(ngx.WARN, "kernel_blocking: scope rebind failed: ", tostring(err))
    end
    rebind_inflight = false
    return ok and true or false, err
end

local function ensure_drop_scope()
    local allowed, why = scope_binding.drop_writes_allowed()
    if allowed then
        return true, nil
    end
    local ok, err = _M.rebind_scope()
    if not ok then
        return false, err or why or "scope_validation_pending"
    end
    allowed, why = scope_binding.drop_writes_allowed()
    if not allowed then
        return false, why or "scope_validation_pending"
    end
    return true, nil
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
function _M.ensure_base(config_arg)
    local payload = scope_binding.ensure_base_payload(config_arg)
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
    local scoped, swhy = ensure_drop_scope()
    if not scoped then
        return false, swhy or "scope_validation_pending"
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
            -- One more rebind+retry after mid-flight invalidation.
            local rb_ok = _M.rebind_scope()
            if rb_ok then
                resp, err = client.request("add", "automatic", {
                    items = {
                        { set = set, family = family, ip = ip, ttl = ttl,
                          source = "automatic", reason = "auto_promotion" },
                    },
                    binding = scope_binding.binding_fields(),
                })
                if resp and resp.ok then
                    return true, nil
                end
                code = err_code(err or (resp and resp.error))
            end
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
    local cursor = 0
    repeat
        local page = _M.list(set, family, cursor)
        for _, entry in ipairs(page.entries or {}) do
            if entry.ip == ip then return true, nil end
        end
        cursor = page.next_cursor
    until not cursor
    return false, nil
end

-- ---------------------------------------------------------------------------
-- list(set, family, cursor) -> { entries = {...}, next_cursor = n|nil }
-- ---------------------------------------------------------------------------
function _M.list_strict(set, family, cursor)
    local resp, err = client.request("list", "automatic", {
        set = set, family = family, cursor = cursor or 0,
    })
    if not resp then
        return nil, err or "list_failed"
    end
    return resp.result or { entries = {}, next_cursor = nil }, nil
end

function _M.list(set, family, cursor)
    local page = _M.list_strict(set, family, cursor)
    return page or { entries = {}, next_cursor = nil }
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
-- Legacy full-snapshot reconcile (non-chunked, for backward compat).
-- ---------------------------------------------------------------------------
function _M.reconcile(snapshot)
    local scoped, swhy = ensure_drop_scope()
    if not scoped then
        return {
            added = 0, updated = 0, removed = 0, preserved = 0, failed = 0,
            error = swhy or "scope_validation_pending",
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
-- chunked_reconcile(chunk) -> result, scope_err?
-- Design §8.3.3: sends a single chunk with snapshot_id/chunk_index/final_chunk.
-- Remove operations included only when final_chunk=true.
-- ---------------------------------------------------------------------------
function _M.chunked_reconcile(chunk)
    local scoped, swhy = ensure_drop_scope()
    if not scoped then
        return nil, swhy or "scope_validation_pending"
    end
    local resp, err = client.request("reconcile", "reconcile", {
        snapshot_id = chunk.snapshot_id,
        chunk_index = chunk.chunk_index,
        final_chunk = chunk.final_chunk,
        desired_generation = chunk.desired_generation,
        policy_generations = chunk.policy_generations,
        total_desired = chunk.total_desired,
        total_chunks = chunk.total_chunks,
        desired = chunk.desired or {},
        remove = chunk.remove or {},
        binding = scope_binding.binding_fields(),
    })
    if not resp then
        local code = err_code(err)
        if is_scope_err(code) then
            scope_binding.invalidate(code)
            return nil, code
        end
        return nil, code
    end
    local r = resp.result or {}
    -- If Helper reports a scope issue inside the response.
    if not resp.ok then
        local code = type(resp.error) == "string" and resp.error or "reconcile_failed"
        if is_scope_err(code) then
            scope_binding.invalidate(code)
            return nil, code
        end
        return {
            added = 0, updated = 0, removed = 0, preserved = 0, failed = #chunk.desired + #chunk.remove,
        }, code
    end
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
