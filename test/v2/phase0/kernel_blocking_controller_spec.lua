-- -*- coding: utf-8 -*-
-- Tests for kernel blocking controller (api/controllers/kernel_blocking.lua).

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.sleep = function() end
_G.ngx.status = 200
_G.ngx.header = { content_type = "application/json; charset=utf-8" }
_G.ngx.req = {
    read_body = function() end,
    get_body_data = function() return '{"ip":"203.0.113.10"}' end,
    get_method = function() return "GET" end,
}
_G.ngx.var = { uri = "/verynginx/kernel-blocking/status" }

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

-- Mock config module
local mock_config = {
    kernel_ip_blocking = {
        enabled = true,
        mode = "observe",
        emergency_pause = false,
        topology = "direct",
        shadow = false,
        scanner = { enabled = true, min_hard_blocks = 3, max_ttl = 86400 },
        canary = { scanner_ttl = 60, cc_ttl = 30 },
        promotion_rate_limit = { limit = 1000, interval = 60, burst = 1000 },
    },
    ip_reputation = {},
}
local config_module = {
    load_from_file = function() end,
    report = function() return require("dkjson").encode(mock_config) end,
    save = function(cfg) return true, nil end,
}
setmetatable(config_module, {
    __index = function(t, k) return mock_config[k] end,
})
package.loaded["core.config"] = config_module

-- Mock executor (always mock)
local _mock_exec = require("core.kernel_blocking.executor_mock")
package.loaded["core.kernel_blocking.executor"] = {
    get_executor = function() return _mock_exec end,
    get_mock = function() return _mock_exec end,
}

-- Mock state machine
local _sm = require("core.kernel_blocking.state_machine")

local controller = require "api.controllers.kernel_blocking"

-- Single api mock; register once, then look up routes by path.
local api = { routes = {} }
function api.register(method, path, handler, auth_required)
    table.insert(api.routes, {
        method = method, path = path, handler = handler,
        auth_required = (auth_required ~= false),
    })
end
controller.register(api)

local function find_route(path)
    for _, r in ipairs(api.routes) do
        if r.path == path then return r end
    end
    return nil
end

describe("Kernel blocking controller", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
        mock_config.kernel_ip_blocking.emergency_pause = false
        mock_config.kernel_ip_blocking.mode = "observe"
        ngx.var.cursor = nil
        ngx.var.page_size = nil
        ngx.var.state = nil
    end)

    it("registers 8 routes", function()
        assert.are.equal(8, #api.routes)
    end)

    it("GET /kernel-blocking/status returns config and counters", function()
        _sm.upsert("203.0.113.10", "scanner", "candidate",
            { block_hits = 5 }, {})

        local route = find_route("/kernel-blocking/status")
        assert.is_truthy(route, "status route registered")

        local resp = route.handler()
        local data = require("dkjson").decode(resp)
        assert.are.equal("success", data.ret)
        assert.are.equal(true, data.data.configured.enabled)
        assert.are.equal("observe", data.data.configured.mode)
        assert.are.equal(0, data.data.counters.installed)
        assert.are.equal(1, data.data.counters.candidates)
    end)

    it("GET /kernel-blocking/candidates returns paginated entries", function()
        _sm.upsert("203.0.113.10", "scanner", "candidate",
            { block_hits = 5 }, {})

        local route = find_route("/kernel-blocking/candidates")
        assert.is_truthy(route, "candidates route registered")

        local resp = route.handler()
        local data = require("dkjson").decode(resp)
        assert.are.equal("success", data.ret)
        assert.is_true(#data.data.entries >= 1)
        assert.are.equal("203.0.113.10", data.data.entries[1].ip)
    end)

    it("GET /kernel-blocking/entries returns installed entries", function()
        _sm.upsert("203.0.113.88", "scanner", "installed",
            { reason = "test" }, { list = "scanner_drop" })

        local route = find_route("/kernel-blocking/entries")
        assert.is_truthy(route, "entries route registered")

        local resp = route.handler()
        local data = require("dkjson").decode(resp)
        assert.are.equal("success", data.ret)
        assert.is_true(#data.data.entries >= 1)
    end)

    it("POST /kernel-blocking/promote installs IP via executor", function()
        ngx.req.get_body_data = function()
            return require("dkjson").encode({ip = "203.0.113.99", policy = "scanner", ttl = 300})
        end

        local route = find_route("/kernel-blocking/promote")
        assert.is_truthy(route, "promote route registered")

        local resp = route.handler()
        local data = require("dkjson").decode(resp)
        assert.are.equal("success", data.ret)
        assert.are.equal("203.0.113.99", data.data.ip)
        assert.are.equal("scanner_drop", data.data.set)

        -- Verify in state machine
        local e = _sm.get("203.0.113.99")
        assert.are.equal("installed", e.state)

        -- Verify in executor (mock checks shared dict)
        local in_set = _mock_exec.contains("scanner_drop", "ipv4", "203.0.113.99")
        assert.is_true(in_set)
    end)

    it("POST /kernel-blocking/clear removes IP from executor", function()
        _mock_exec.add("scanner_drop", "ipv4", "203.0.113.50", 300)
        _sm.upsert("203.0.113.50", "scanner", "installed", {}, { list = "scanner_drop" })

        ngx.req.get_body_data = function()
            return require("dkjson").encode({ip = "203.0.113.50"})
        end

        local route = find_route("/kernel-blocking/clear")
        assert.is_truthy(route, "clear route registered")

        local resp = route.handler()
        local data = require("dkjson").decode(resp)
        assert.are.equal("success", data.ret)
        assert.are.equal(1, data.data.removed)

        -- Verify state machine updated
        local e = _sm.get("203.0.113.50")
        assert.are.equal("cleared", e.state)
    end)

    it("POST /kernel-blocking/pause toggles emergency_pause", function()
        ngx.req.get_body_data = function()
            return require("dkjson").encode({paused = true})
        end

        local route = find_route("/kernel-blocking/pause")
        assert.is_truthy(route, "pause route registered")

        local resp = route.handler()
        local data = require("dkjson").decode(resp)
        assert.are.equal("success", data.ret)
        assert.are.equal(true, data.data.paused)
    end)

    it("POST /kernel-blocking/flush-auto calls executor.flush_owned", function()
        _mock_exec.add("scanner_drop", "ipv4", "203.0.113.70", 300)

        local route = find_route("/kernel-blocking/flush-auto")
        assert.is_truthy(route, "flush-auto route registered")

        local resp = route.handler()
        local data = require("dkjson").decode(resp)
        assert.are.equal("success", data.ret)
        assert.is_true(data.data.removed >= 1)
    end)

    it("POST /kernel-blocking/reconcile triggers reconciliation", function()
        local route = find_route("/kernel-blocking/reconcile")
        assert.is_truthy(route, "reconcile route registered")

        local resp = route.handler()
        local data = require("dkjson").decode(resp)
        assert.are.equal("success", data.ret)
    end)
end)
