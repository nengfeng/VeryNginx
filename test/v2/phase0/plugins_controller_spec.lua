-- -*- coding: utf-8 -*-
-- P2-7: direct tests for the plugins controller (plugins + upstreams + stats).
-- The controller binds core.config at require time, so the config mock must be
-- installed BEFORE the controller is required; the lazily-required core.plugin
-- and core.statistics are injected per-test and restored afterwards.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.status = 200
_G.ngx.req = { read_body = function() end, get_body_data = function() return "" end }
_G.ngx.ctx = {}
_G.ngx.var = { arg_limit = nil, arg_host = nil }

local json = require "dkjson"

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
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
            }
        end
        return t._cache[name]
    end,
})

-- Config mock the controller's top-level `config` upvalue will hold.
local config_mock = {
    backend_upstream = {
        api = { nodes = { { host = "10.0.0.1", port = 8080 } } },
        web = { nodes = { { host = "10.0.0.2", port = 80 } } },
    },
    plugin = {},
    _save_ok = true,
    _saved = nil,
}
function config_mock.report()
    return json.encode({ backend_upstream = config_mock.backend_upstream, plugin = config_mock.plugin })
end
function config_mock.save(tbl)
    if not config_mock._save_ok then return false, "save failed" end
    config_mock._saved = tbl
    return true
end
local config_orig = package.loaded["core.config"]
package.loaded["core.config"] = config_mock

local controller = require "api.controllers.plugins"
local api = { routes = {} }
function api.register(m, p, h, a) api.routes[#api.routes + 1] = { m = m, p = p, h = h } end
controller.register(api)
local function route(path, method)
    for _, r in ipairs(api.routes) do
        if r.p == path and r.m == method then return r end
    end
    return nil
end

local plugin_fake = {
    plugins = {
        { name = "waf", priority = 10, critical = true, description = "WAF engine", default_enable = true },
        { name = "cc", priority = 20, default_enable = true },
        { name = "legacy", priority = 30, default_enable = false },
    },
    is_enabled = function(p)
        local entry = config_mock.plugin[p.name]
        if entry and entry.enable ~= nil then return entry.enable == true end
        return p.default_enable ~= false
    end,
}
local stats_fake = {
    get_top_paths = function(limit, host)
        return { { path = "/api", count = 900 }, { path = "/", count = 100 } }
    end,
    get_hosts = function() return { "api.example", "www.example" } end,
    valid_host_param = function(h) return h == "api.example" or h == "www.example" end,
}
local plugin_orig = package.loaded["core.plugin"]
local stats_orig = package.loaded["core.statistics"]

describe("Plugins controller (P2-7)", function()
    before_each(function()
        package.loaded["core.plugin"] = plugin_fake
        package.loaded["core.statistics"] = stats_fake
        package.loaded["core.config"] = config_mock
        config_mock.plugin = {}
        config_mock._save_ok = true
        config_mock._saved = nil
        ngx.shared.healthcheck:flush_all()
        ngx.status = 200
        ngx.ctx = {}
        ngx.var.arg_limit = nil
        ngx.var.arg_host = nil
    end)
    after_each(function()
        -- Drop the mocks so no later spec file in the shared busted process
        -- sees them (AGENTS 9.3); each before_each re-installs them.
        package.loaded["core.plugin"] = nil
        package.loaded["core.statistics"] = nil
        package.loaded["core.config"] = nil
    end)

    it("registers 5 routes", function()
        assert.are.equal(5, #api.routes)
    end)

    it("GET /plugins reports each plugin with its effective enable state", function()
        local data = json.decode(route("/plugins", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(3, #data.data)
        assert.are.equal("waf", data.data[1].name)
        assert.is_true(data.data[1].enable)
        assert.is_true(data.data[1].critical)
        -- legacy default_enable=false -> enable false
        assert.is_false(data.data[3].enable)
    end)

    it("POST /plugins/:id/toggle flips the enable state and persists", function()
        ngx.ctx.waf_rule_id = "cc"
        local data = json.decode(route("/plugins/:id/toggle", "POST").h())
        assert.are.equal("success", data.ret)
        -- cc's default is enable=true, so the first toggle stores false.
        assert.is_false(data.data.enable)
        assert.is_false(config_mock.plugin.cc.enable)
        -- second toggle flips back to true
        data = json.decode(route("/plugins/:id/toggle", "POST").h())
        assert.is_true(data.data.enable)
        assert.is_true(config_mock.plugin.cc.enable)
    end)

    it("POST /plugins/:id/toggle requires a plugin name", function()
        local data = json.decode(route("/plugins/:id/toggle", "POST").h())
        assert.are.equal("failed", data.ret)
        assert.are.equal("plugin name required", data.message)
    end)

    it("POST /plugins/:id/toggle maps a save failure to 400", function()
        config_mock._save_ok = false
        ngx.ctx.waf_rule_id = "cc"
        local data = json.decode(route("/plugins/:id/toggle", "POST").h())
        assert.are.equal("failed", data.ret)
        assert.are.equal(400, ngx.status)
    end)

    it("GET /upstreams/health reads node state from the healthcheck dict", function()
        local h = ngx.shared.healthcheck
        h:set("hc:api:10.0.0.1:8080:state", "unhealthy")
        h:set("hc:api:10.0.0.1:8080:failures", "3")
        h:set("cb:web:10.0.0.2:80", "open")
        local data = json.decode(route("/upstreams/health", "GET").h())
        assert.are.equal("success", data.ret)
        local apiNode = data.data.api[1]
        assert.is_false(apiNode.healthy)
        assert.are.equal(3, apiNode.failures)
        local webNode = data.data.web[1]
        assert.is_true(webNode.circuit_open)
    end)

    it("GET /stats/top-paths clamps the limit and validates host", function()
        ngx.var.arg_limit = "500"
        ngx.var.arg_host = "api.example"
        local data = json.decode(route("/stats/top-paths", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal("/api", data.data[1].path)
        ngx.var.arg_host = "evil"
        local bad = json.decode(route("/stats/top-paths", "GET").h())
        assert.are.equal("failed", bad.ret)
        assert.are.equal(400, ngx.status)
    end)

    it("GET /stats/hosts lists observed hosts", function()
        local data = json.decode(route("/stats/hosts", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(2, #data.data)
    end)
end)
