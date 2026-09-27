-- -*- coding: utf-8 -*-
-- Tests for the per-host statistics dimension (core/statistics.lua).

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

-- ---- ngx stub (self-contained, no spec_helper) ----
if not _G.ngx then _G.ngx = {} end
_G.ngx.log = function() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.now = function() return 1700000000 end
_G.ngx.worker = { id = function() return 0 end }
_G.ngx.timer = { every = function() end, at = function() end }

local function new_mock_dict()
    local store = {}
    local dict = {}
    function dict:get(key) return store[key] end
    function dict:set(key, value, ttl) store[key] = value; return true end
    function dict:incr(key, value, init, ttl)
        local cur = store[key]
        if cur == nil then cur = init or 0 end
        cur = cur + (value or 1)
        store[key] = cur
        return cur
    end
    function dict:delete(key) store[key] = nil; return true end
    dict._store = store
    return dict
end

_G.ngx.shared = { statistics = new_mock_dict() }
_G.ngx.var = {
    host = "example.com",
    uri = "/index.php",
    status = "200",
    body_bytes_sent = "100",
    request_time = "0.05",
    server_name = "example.com",
}

-- ---- config fake (statistics-only; resolve_path for persist/restore) ----
package.preload["core.config"] = function()
    return {
        statistics = { max_hosts = 50, max_uri_keys = 10000 },
        resolve_path = function() return "/tmp/vn_stats_test" end,
    }
end

local json = require "dkjson"
local _orig_random = math.random

describe("statistics per-host dimension", function()
    before_each(function()
        package.loaded["core.statistics"] = nil
        package.loaded["core.dict_guard"] = nil
        _G.ngx.shared.statistics = new_mock_dict()
        math.random = function() return 1 end  -- force the 1-in-10 sample hit
        os.execute("rm -rf /tmp/vn_stats_test 2>/dev/null")
    end)

    after_each(function()
        math.random = _orig_random
        package.preload["core.config"] = nil
        package.loaded["core.config"] = nil
        package.loaded["core.statistics"] = nil
        package.loaded["core.dict_guard"] = nil
    end)

    it("normalize_host lowercases, strips trailing dot, replaces separators", function()
        local stats = require "core.statistics"
        assert.are.equal("example.com", stats.normalize_host("Example.COM"))
        assert.are.equal("example.com", stats.normalize_host("example.com."))
        assert.are.equal("___1_", stats.normalize_host("[::1]"))
        -- empty/nil falls back to server_name (stub = "example.com")
        assert.are.equal("example.com", stats.normalize_host(""))
        assert.are.equal("example.com", stats.normalize_host(nil))
        -- length bound
        assert.are.equal(64, #stats.normalize_host(string.rep("a", 100)))
    end)

    it("normalize_host yields _ when both host and server_name are empty", function()
        local stats = require "core.statistics"
        local saved = _G.ngx.var.server_name
        _G.ngx.var.server_name = ""
        assert.are.equal("_", stats.normalize_host(nil))
        _G.ngx.var.server_name = saved
    end)

    it("valid_host_param accepts normalized tokens only", function()
        local stats = require "core.statistics"
        assert.truthy(stats.valid_host_param("example.com"))
        assert.truthy(stats.valid_host_param("example_com"))
        assert.truthy(stats.valid_host_param("example-com.io"))
        assert.is_false(stats.valid_host_param("example.com:8080"))
        assert.is_false(stats.valid_host_param("a b"))
        assert.is_false(stats.valid_host_param(""))
        assert.is_false(stats.valid_host_param(string.rep("a", 65)))
    end)

    it("log_request writes host-scoped keys", function()
        local stats = require "core.statistics"
        stats.log_request({})
        local store = _G.ngx.shared.statistics._store
        assert.are.equal(1, store["1m:example.com:/index.php:count"])
        assert.truthy(store["index:1m:example.com"])
        assert.truthy(store["hosts:1m"])
    end)

    it("report aggregates across hosts and filters by host", function()
        local stats = require "core.statistics"
        local shared = _G.ngx.shared.statistics

        -- host A: /index.php = 100 (90x200, 10x404)
        shared:set("1m:example.com:/index.php:count", 100)
        shared:set("1m:example.com:/index.php:bytes", 1000)
        shared:set("1m:example.com:/index.php:time", 1.5)
        shared:set("1m:example.com:/index.php:status_200", 90)
        shared:set("1m:example.com:/index.php:status_404", 10)
        shared:set("index:1m:example.com", json.encode({ "/index.php" }))

        -- host B: /index.php = 50, /api = 200
        shared:set("1m:api.example.com:/index.php:count", 50)
        shared:set("1m:api.example.com:/index.php:bytes", 500)
        shared:set("1m:api.example.com:/index.php:time", 0.5)
        shared:set("1m:api.example.com:/index.php:status_200", 50)
        shared:set("1m:api.example.com:/api:count", 200)
        shared:set("1m:api.example.com:/api:bytes", 2000)
        shared:set("1m:api.example.com:/api:time", 2.0)
        shared:set("1m:api.example.com:/api:status_200", 200)
        shared:set("index:1m:api.example.com", json.encode({ "/api", "/index.php" }))

        shared:set("hosts:1m", json.encode({ "example.com", "api.example.com" }))

        -- Aggregated (no host): /index.php = 150, /api = 200
        local all = json.decode(stats.report("short"))
        assert.are.equal(150, all["/index.php"].count)
        assert.are.equal(1500, all["/index.php"].bytes)
        assert.are.equal(200, all["/api"].count)

        -- Filtered (single host)
        local one = json.decode(stats.report("short", "example.com"))
        assert.are.equal(100, one["/index.php"].count)
        assert.is_nil(one["/api"])
    end)

    it("get_top_paths filters by host", function()
        local stats = require "core.statistics"
        local shared = _G.ngx.shared.statistics
        shared:set("1m:example.com:/a:count", 10)
        shared:set("1m:example.com:/a:bytes", 100)
        shared:set("1m:example.com:/a:time", 1)
        shared:set("1m:api.example.com:/b:count", 99)
        shared:set("1m:api.example.com:/b:bytes", 990)
        shared:set("1m:api.example.com:/b:time", 1)
        shared:set("index:1m:example.com", json.encode({ "/a" }))
        shared:set("index:1m:api.example.com", json.encode({ "/b" }))
        shared:set("hosts:1m", json.encode({ "example.com", "api.example.com" }))

        local all = stats.get_top_paths(20)
        assert.are.equal(2, #all)

        local one = stats.get_top_paths(20, "example.com")
        assert.are.equal(1, #one)
        assert.are.equal("/a", one[1].uri)
    end)

    it("get_hosts returns the union of 1m and all, sorted", function()
        local stats = require "core.statistics"
        local shared = _G.ngx.shared.statistics
        shared:set("hosts:1m", json.encode({ "b.example.com", "a.example.com" }))
        shared:set("hosts:all", json.encode({ "c.example.com" }))

        local hosts = stats.get_hosts()
        assert.are.same({ "a.example.com", "b.example.com", "c.example.com" }, hosts)
    end)

    it("persist writes a v2 host-nested payload", function()
        os.execute("mkdir -p /tmp/vn_stats_test/configs 2>/dev/null")
        local stats = require "core.statistics"
        local shared = _G.ngx.shared.statistics
        shared:set("all:example.com:/x:count", 7)
        shared:set("all:example.com:/x:bytes", 70)
        shared:set("all:example.com:/x:time", 0.7)
        shared:set("all:example.com:/x:status_200", 7)
        shared:set("index:all:example.com", json.encode({ "/x" }))
        shared:set("hosts:all", json.encode({ "example.com" }))

        stats.persist()

        local f = io.open("/tmp/vn_stats_test/configs/statistics.json", "r")
        assert.truthy(f, "statistics.json should exist after persist")
        if f then
            local raw = f:read("*all")
            f:close()
            local decoded = json.decode(raw)
            assert.are.equal(2, decoded.v)
            assert.are.equal(7, decoded.data["example.com"]["/x"].count)
        end
    end)

    it("restore skips legacy flat (v1) payloads", function()
        os.execute("mkdir -p /tmp/vn_stats_test/configs 2>/dev/null")
        local legacy = { ["/legacy"] = { count = 3, bytes = 30, time = 0.3 } }
        local f = io.open("/tmp/vn_stats_test/configs/statistics.json", "w")
        f:write(json.encode(legacy))
        f:close()

        local stats = require "core.statistics"
        stats.restore()

        -- Nothing should be restored into the shdict
        assert.is_nil(_G.ngx.shared.statistics._store["all:legacy:/legacy:count"])
        assert.is_nil(_G.ngx.shared.statistics._store["hosts:all"])
    end)
end)
