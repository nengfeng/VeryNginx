-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking executor via IPC Protocol v1.
--             Wraps ipc_client to provide the same interface as
--             executor_mock. Connects to the privileged Firewall Helper
--             over Unix Domain Socket.

local _M = {}

local client = require "core.kernel_blocking.ipc_client"

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
    local resp, err = client.request_safe("ensure_base", "automatic", config or {})
    if resp and resp.ok then
        return true, nil
    end
    return false, err or "ensure_base_failed"
end

-- ---------------------------------------------------------------------------
-- add(set, family, ip, ttl) -> ok, error?
-- ---------------------------------------------------------------------------
function _M.add(set, family, ip, ttl)
    local resp, err = client.request_safe("add", "automatic", {
        items = {
            { set = set, family = family, ip = ip, ttl = ttl,
              source = "automatic", reason = "auto_promotion" },
        },
    })
    if resp and resp.ok then
        return true, nil
    end
    return false, err or "add_failed"
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
    -- Use list(1) as contains; full scan if needed
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
-- entries: { { ip = ..., family = "ipv4"|"ipv6" }, ... }
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
-- desired_snapshot: flat list of { set, family, ip, ttl, mode }
-- ---------------------------------------------------------------------------
function _M.reconcile(snapshot)
    local resp = client.request_safe("reconcile", "reconcile", {
        snapshot = snapshot or {},
    })
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
    return resp.result or { state = "degraded", instance_id = "unknown" }
end

return _M
