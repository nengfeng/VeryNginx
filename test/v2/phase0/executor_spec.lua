-- -*- coding: utf-8 -*-
-- Tests for executor wrapper + IPC adapter.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5
_G.ngx.time = function() return 1700000000 end
local function mock_tcp()
    local c = {}
    function c:settimeouts() end
    function c:connect() return nil, "refused" end
    function c:send() return nil end
    function c:receiveany() return nil, "timeout" end
    function c:setkeepalive() end
    function c:close() end
    return c
end
_G.ngx.socket = { tcp = mock_tcp }
_G.ngx.shared = setmetatable({_cache = {}}, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v) st[k] = v; return true, nil end,
                add = function(_, k, v) if st[k] then return false, "exists" end; st[k] = v; return true, nil end,
                incr = function(_, k, d, i) if st[k] == nil then st[k] = (i or 0) end; st[k] = st[k] + d; return st[k], nil end,
                delete = function(_, k) st[k] = nil end,
                expire = function() end,
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
            }
        end
        return t._cache[name]
    end,
})

local exec_mod = require "core.kernel_blocking.executor"

describe("Executor wrapper", function()
    it("get_executor returns mock by default", function()
        local e = exec_mod.get_executor()
        assert.truthy(e)
        assert.truthy(e.add)
        assert.truthy(e.delete)
        assert.truthy(e.list)
    end)

    it("get_mock always returns mock", function()
        local e = exec_mod.get_mock()
        assert.truthy(e)
        -- Mock's add returns true on success
        local ok, _ = e.add("scanner_drop", "ipv4", "203.0.113.1", 3600)
        assert.is_true(ok)
    end)
end)

describe("IPC executor adapter", function()
    it("implements the full 8-method contract", function()
        local ipc = require "core.kernel_blocking.executor_ipc"
        local contract = require "core.kernel_blocking.executor_contract"
        for _, method in ipairs(contract.METHODS) do
            assert.truthy(ipc[method], "ipc_executor missing method: " .. method)
        end
    end)

    it("safe request returns default on failure (no crash)", function()
        local ipc = require "core.kernel_blocking.executor_ipc"
        -- Without a running Helper, request_safe should return defaults
        local resp = ipc.probe()
        assert.truthy(resp)
    end)
end)

describe("replace_allow_snapshot", function()
    it("replaces the allow set in mock executor", function()
        local mock = require "core.kernel_blocking.executor_mock"
        -- Add some entries first
        mock.add("allow", "ipv4", "10.0.0.1", 0)
        mock.add("allow", "ipv4", "10.0.0.2", 0)
        -- Replace with new entries
        local ok, _ = mock.replace_allow_snapshot({
            { ip = "192.168.1.1", family = "ipv4" },
            { ip = "192.168.1.2", family = "ipv4" },
        })
        assert.is_true(ok)
        -- Old entries should be gone
        local old_gone, _ = mock.contains("allow", "ipv4", "10.0.0.1")
        assert.is_false(old_gone)
        -- New entries should exist
        local new_there, _ = mock.contains("allow", "ipv4", "192.168.1.1")
        assert.is_true(new_there)
    end)

    it("handles empty entries list (clears allow set)", function()
        local mock = require "core.kernel_blocking.executor_mock"
        mock.add("allow", "ipv4", "10.0.0.1", 0)
        local ok, _ = mock.replace_allow_snapshot({})
        assert.is_true(ok)
        local list = mock.list("allow", "ipv4", 0)
        assert.are.equal(0, #list.entries)
    end)
end)
