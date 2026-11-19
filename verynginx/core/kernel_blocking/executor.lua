-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking executor — unified interface.
--             Selects between mock_executor (shared-dict backed) and
--             ipc_executor (IPC Protocol v1 to privileged Helper).
--
--             Selection logic (mode-aware):
--               mode="enforce" → always use ipc_executor (real writes).
--                                  Falls back to mock if IPC unavailable (fail-open).
--               mode="observe" + shadow=true → use ipc_executor (dry-run with real reads)
--               mode="observe" + shadow=false → use mock_executor (Phase 2 dry-run)

local _M = {}

local mock = require "core.kernel_blocking.executor_mock"

-- Fail-closed executor used when enforce mode cannot load the IPC adapter.
-- It must NOT be mock: mock reports success while writing nothing to the
-- kernel, which would make the panel believe IPs are blocked when they are
-- not. Every mutating method returns an error so promotion/reconcile surfaces
-- the failure instead of silently pretending.
local function unavailable_executor()
    return {
        probe = function() return { protocol_min = 1, protocol_max = 1,
            capabilities = {}, version = "unavailable" } end,
        ensure_base = function() return false, "ipc_executor_unavailable" end,
        add = function() return false, "ipc_executor_unavailable" end,
        delete = function() return false, "ipc_executor_unavailable" end,
        contains = function() return false, "ipc_executor_unavailable" end,
        list = function() return nil, "ipc_executor_unavailable" end,
        list_strict = function() return nil, "ipc_executor_unavailable" end,
        replace_allow_snapshot = function() return false, "ipc_executor_unavailable" end,
        reconcile = function()
            return { added = 0, updated = 0, removed = 0, preserved = 0,
                     failed = 0, error = "ipc_executor_unavailable" }
        end,
        flush_owned = function() return false, { removed = 0 }, "ipc_executor_unavailable" end,
        health = function() return { state = "unreachable",
            error = "ipc_executor_unavailable" } end,
    }
end

-- ipc_executor is lazy-loaded (may not be available without Helper process)
local ipc_exec = nil
local function get_ipc()
    if not ipc_exec then
        local ok, mod = pcall(require, "core.kernel_blocking.executor_ipc")
        if ok then ipc_exec = mod end
    end
    return ipc_exec
end

-- ---------------------------------------------------------------------------
-- Returns the appropriate executor table based on config.
-- @return table: { probe, ensure_base, add, delete, contains, list,
--                  replace_allow_snapshot, reconcile, flush_owned, health }
-- ---------------------------------------------------------------------------
function _M.get_executor()
    local config = require "core.config"
    local kb_cfg = config and config.kernel_ip_blocking
    if not kb_cfg then return mock end

    -- Enforce mode: always use real Helper for writes. If the IPC adapter
    -- itself cannot be loaded, fail closed — never pretend the kernel was
    -- written.
    if kb_cfg.mode == "enforce" then
        local ipc = get_ipc()
        if ipc then return ipc end
        ngx.log(ngx.ERR, "kernel_blocking: enforce mode but ipc_executor unavailable; failing closed")
        return unavailable_executor()
    end

    -- Observe mode with shadow: use IPC for real reads (dry-run writes)
    if kb_cfg.shadow then
        local ipc = get_ipc()
        if ipc then return ipc end
        ngx.log(ngx.WARN, "kernel_blocking: shadow mode requested but ",
            "ipc_executor unavailable, falling back to mock")
    end

    -- Default: mock executor (Phase 2 dry-run)
    return mock
end

-- For callers that need always-mock (e.g., Phase 2 dry-run):
function _M.get_mock()
    return mock
end

return _M
