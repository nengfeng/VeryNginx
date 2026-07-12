-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking executor — unified interface.
--             Selects between mock_executor (shared-dict backed) and
--             ipc_executor (IPC Protocol v1 to privileged Helper).
--
--             Selection is controlled by config:
--               kernel_ip_blocking.shadow = true → use ipc_executor
--               otherwise → use mock_executor (default)

local _M = {}

local mock = require "core.kernel_blocking.executor_mock"

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
--                  reconcile, flush_owned, health }
-- ---------------------------------------------------------------------------
function _M.get_executor()
    local config = require "core.config"
    local kb_cfg = config and config.kernel_ip_blocking
    if kb_cfg and kb_cfg.shadow then
        local ipc = get_ipc()
        if ipc then return ipc end
        ngx.log(ngx.WARN, "kernel_blocking: shadow mode requested but ",
            "ipc_executor unavailable, falling back to mock")
    end
    return mock
end

-- For callers that need always-mock (e.g., Phase 2 dry-run):
function _M.get_mock()
    return mock
end

return _M
