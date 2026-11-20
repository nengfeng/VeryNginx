-- -*- coding: utf-8 -*-
-- P2-7: direct tests for the live-traffic controller.
-- The controller binds core.statistics and core.live_stats at require time;
-- resty.http and core.mysql_monitor are required lazily inside the handler.
-- Disk / log probes (io.popen df, io.open of /data/wwwlogs) are harmless in
-- the test environment: the probes return empty tables when the paths
-- don't exist, which is exactly what the assertions check for.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.now = function() return 1700000000 end
_G.ngx.status = 200
_G.ngx.ctx = {}
_G.ngx.var = {
    arg_minutes = nil,
    connections_active = "3",
    connections_reading = "0",
    connections_writing = "1",
    connections_waiting = "2",
}
-- Shared-dict fake (metrics dict for log-size growth tracking).
_G.ngx.shared = setmetatable({ _cache = {} }, {
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

local json = require "dkjson"

-- Behaviour switches the tests flip.
local live_cfg = {
    hosts = { "b.example", "a.example" },
    minutes_seen = nil,
}
local live_stats_fake = {}
function live_stats_fake.hosts(minutes)
    live_cfg.minutes_seen = minutes
    return live_cfg.hosts
end
function live_stats_fake.host_series(host, _minutes)
    if host == "a.example" then
        return {
            { minute = 1, requests = 10, clients = 4, shapes = { ua = { curl = 5 } } },
            { minute = 2, requests = 20, clients = 8, shapes = {} },
        }
    end
    return { { minute = 1, requests = 5, clients = 2 } }
end
function live_stats_fake.is_backend_failure(code)
    return (code >= 500 and code < 600) or code == 499
end
function live_stats_fake.baseline(host) return { avg_requests = 8, host = host } end
function live_stats_fake.anomalies(host, _series)
    if host == "a.example" then
        return { { level = "warn", kind = "spike" } }
    end
    return { { level = "critical", kind = "error_storm" } }
end
function live_stats_fake.history(host, _n) return {} end
function live_stats_fake.hour_history(host, _n) return {} end

local statistics_fake = {}
function statistics_fake.get_host_status(host, _window)
    if host == "a.example" then
        -- 429 (rate limiter working) and 403 (WAF blocking) must NOT count
        -- as backend failures; only 5xx/499 do.
        return { [200] = 7, [429] = 5, [403] = 0, [502] = 3 }
    end
    return { [200] = 2 }
end

local http_cfg = { res = nil, err = "connection timeout" }
local http_fake = {}
function http_fake.new(_self)
    local client = {}
    function client.set_timeout(_c, _ms) end
    function client.request_uri(_c, _url, _opts)
        return http_cfg.res, http_cfg.err
    end
    return client
end
local mysql_fake = {}
function mysql_fake.last() return { ok = true, threads_connected = 4 } end

local stats_orig = package.loaded["core.statistics"]
local live_orig = package.loaded["core.live_stats"]
package.loaded["core.statistics"] = statistics_fake
package.loaded["core.live_stats"] = live_stats_fake

local controller = require "api.controllers.live"
local api = { routes = {} }
function api.register(m, p, h, a) api.routes[#api.routes + 1] = { m = m, p = p, h = h } end
controller.register(api)
local function route(path, method)
    for _, r in ipairs(api.routes) do
        if r.p == path and r.m == method then return r end
    end
    return nil
end

describe("Live controller (P2-7)", function()
    before_each(function()
        package.loaded["resty.http"] = http_fake
        package.loaded["core.mysql_monitor"] = mysql_fake
        http_cfg.res, http_cfg.err = nil, "connection timeout"
        ngx.var.arg_minutes = nil
        ngx.var.connections_active = "3"
        ngx.var.connections_reading = "0"
        ngx.var.connections_writing = "1"
        ngx.var.connections_waiting = "2"
        ngx.shared.metrics:flush_all()
        ngx.status = 200
    end)
    after_each(function()
        package.loaded["resty.http"] = nil
        package.loaded["core.mysql_monitor"] = nil
        package.loaded["core.statistics"] = stats_orig
        package.loaded["core.live_stats"] = live_orig
    end)

    it("registers the single GET /live route", function()
        assert.are.equal(1, #api.routes)
        assert.equal("/live", api.routes[1].p)
        assert.equal("GET", api.routes[1].m)
    end)

    it("clamps the minutes window to 1..30 with a default of 10", function()
        ngx.var.arg_minutes = "500"
        json.decode(route("/live", "GET").h())
        assert.are.equal(30, live_cfg.minutes_seen)
        ngx.var.arg_minutes = "0"
        json.decode(route("/live", "GET").h())
        assert.are.equal(1, live_cfg.minutes_seen)
        ngx.var.arg_minutes = nil
        json.decode(route("/live", "GET").h())
        assert.are.equal(10, live_cfg.minutes_seen)
    end)

    it("sorts hosts and aggregates anomalies most-severe first", function()
        local data = json.decode(route("/live", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(2, #data.data.hosts)
        assert.are.equal("a.example", data.data.hosts[1].host)
        assert.are.equal("b.example", data.data.hosts[2].host)
        -- critical (b.example) must come before warn (a.example)
        assert.are.equal("critical", data.data.anomalies[1].level)
        assert.are.equal("b.example", data.data.anomalies[1].host)
        assert.are.equal("warn", data.data.anomalies[2].level)
        assert.are.equal("a.example", data.data.anomalies[2].host)
    end)

    it("computes failing_pct excluding WAF/rate-limit responses", function()
        local data = json.decode(route("/live", "GET").h())
        local a = data.data.hosts[1]
        -- total 15 (7+5+3); only the 3 x 502 are backend failures -> 20%
        assert.are.equal(15, a.status_total)
        assert.are.equal(20, a.failing_pct)
        local b = data.data.hosts[2]
        assert.are.equal(0, b.failing_pct)
    end)

    it("reports the nginx connection counters and fpm status", function()
        http_cfg.res = { status = 200, body = "active processes: 1\ncurpool: www\n" }
        local data = json.decode(route("/live", "GET").h())
        local backend = data.data.backend
        assert.are.equal(3, backend.nginx.active)
        assert.are.equal(1, backend.nginx.writing)
        assert.are.equal(2, backend.nginx.waiting)
        assert.is_true(backend.fpm.available)
        assert.are.equal(1, backend.fpm.active_processes)
        assert.are.equal("www", backend.fpm.curpool)
    end)

    it("reports an fpm outage as available=false with the error", function()
        local data = json.decode(route("/live", "GET").h())
        assert.is_false(data.data.backend.fpm.available)
        assert.are.equal("connection timeout", data.data.backend.fpm.error)
    end)

    it("includes the mysql monitor reading and empty log probes", function()
        local data = json.decode(route("/live", "GET").h())
        assert.is_true(data.data.backend.mysql.ok)
        assert.are.equal(4, data.data.backend.mysql.threads_connected)
        assert.is_table(data.data.backend.logs)
        assert.is_table(data.data.backend.disk)
    end)

    it("reports the sampling rate so counts are never silently low", function()
        local data = json.decode(route("/live", "GET").h())
        assert.are.equal(10, data.data.sample_rate)
        assert.are.equal(1700000000, data.data.generated_at)
    end)
end)
