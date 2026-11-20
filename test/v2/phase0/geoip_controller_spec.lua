-- -*- coding: utf-8 -*-
-- P2-7: direct tests for the geoip controller.
-- The controller lazily requires core.geoip / core.geoip_updater /
-- core.ip_quality / api.helpers / core.config inside handlers, so the fakes
-- are injected in before_each and restored in after_each.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.status = 200
_G.ngx.req = { read_body = function() end, get_body_data = function() return "" end }
_G.ngx.ctx = {}
_G.ngx.var = { arg_ip = nil, arg_limit = nil, arg_host = nil }

local json = require "dkjson"

local controller = require "api.controllers.geoip"
local api = { routes = {} }
function api.register(m, p, h, a) api.routes[#api.routes + 1] = { m = m, p = p, h = h } end
controller.register(api)
local function route(path, method)
    for _, r in ipairs(api.routes) do
        if r.p == path and r.m == method then return r end
    end
    return nil
end

-- Fake modules; behaviour switches are flipped per test.
local g = {
    lookup_result = nil,          -- table -> found; nil -> not found / db down
    available = true,
    available_err = "no db",
    geodb_path = "/opt/verynginx/geoip.mmdb",
    quality = nil,               -- table -> entry; nil -> unavailable
    quality_err = "rate limited",
}
local geoip_fake = {}
function geoip_fake.lookup(_) return g.lookup_result end
function geoip_fake.is_available(_) return g.available, g.available_err end
function geoip_fake.get_geodb_path() return g.geodb_path end
function geoip_fake.get_stats(_) return { db_loaded = g.available } end
function geoip_fake.reload() end
-- NOTE: methods are defined after the table literal - inside the
-- constructor the local's scope has not started, so a bare self-name
-- there would resolve to the (unset) global and fail at call time.
local updater_fake = { _ok = true, _err = "up to date", _status = nil }
function updater_fake.get_status() return { last_check = 0, version = "2026-10" } end
function updater_fake.check_update()
    return updater_fake._ok, updater_fake._err, updater_fake._status
end
local ipq_fake = {}
function ipq_fake.lookup(_) return g.quality, g.quality_err end
local helpers_fake = {}
function helpers_fake.is_valid_ip(ip)
    if type(ip) ~= "string" then return false end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return ip:find(":") ~= nil end
    return tonumber(a) <= 255 and tonumber(b) <= 255
        and tonumber(c) <= 255 and tonumber(d) <= 255
end
function helpers_fake.redact_geoip_credentials(section)
    if section.api_key then section.api_key = "(redacted)" end
    if section.license_key then section.license_key = "(redacted)" end
end
local config_fake = {
    geoip = { geodb_path = g.geodb_path, api_key = "sekret" },
    _saved = nil,
    _save_ok = true,
}
function config_fake.report()
    return json.encode({ geoip = { geodb_path = g.geodb_path } })
end
function config_fake.save(tbl)
    if not config_fake._save_ok then return false, "dict full" end
    config_fake._saved = tbl
    return true
end
local KEYS = {
    "core.geoip", "core.geoip_updater", "core.ip_quality", "api.helpers", "core.config",
}
local orig = {}
for _, k in ipairs(KEYS) do orig[k] = package.loaded[k] end

describe("GeoIP controller (P2-7)", function()
    before_each(function()
        package.loaded["core.geoip"] = geoip_fake
        package.loaded["core.geoip_updater"] = updater_fake
        package.loaded["core.ip_quality"] = ipq_fake
        package.loaded["api.helpers"] = helpers_fake
        package.loaded["core.config"] = config_fake
        g.lookup_result = nil
        g.available = true
        g.quality = nil
        ngx.status = 200
        ngx.ctx = {}
        ngx.var.arg_ip = nil
        config_fake._saved = nil
        config_fake._save_ok = true
        updater_fake._ok, updater_fake._err, updater_fake._status = true, "up to date", nil
    end)
    after_each(function()
        for _, k in ipairs(KEYS) do package.loaded[k] = orig[k] end
    end)

    it("registers 7 routes", function()
        assert.are.equal(7, #api.routes)
    end)

    it("GET /geoip/lookup requires the ip parameter", function()
        local data = json.decode(route("/geoip/lookup", "GET").h())
        assert.are.equal("failed", data.ret)
        assert.are.equal(400, ngx.status)
        assert.are.equal("ip parameter required", data.message)
    end)

    it("GET /geoip/lookup returns the record", function()
        ngx.var.arg_ip = "203.0.113.5"
        g.lookup_result = { country = "CN", asn = 4134 }
        local data = json.decode(route("/geoip/lookup", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal("CN", data.data.country)
    end)

    it("GET /geoip/lookup distinguishes a missing DB from a missing IP", function()
        ngx.var.arg_ip = "203.0.113.5"
        g.lookup_result = nil
        g.available = false
        local data = json.decode(route("/geoip/lookup", "GET").h())
        assert.are.equal("failed", data.ret)
        assert.match("GeoIP database not available", data.message)
        assert.match(g.geodb_path, data.message)
    end)

    it("GET /geoip/quality rejects an invalid IP", function()
        ngx.var.arg_ip = "999.0.0.1"
        local data = json.decode(route("/geoip/quality", "GET").h())
        assert.are.equal("failed", data.ret)
        assert.are.equal(400, ngx.status)
        assert.are.equal("invalid IP", data.message)
    end)

    it("GET /geoip/quality reports unavailable as ret=failed at 200", function()
        ngx.var.arg_ip = "203.0.113.5"
        local data = json.decode(route("/geoip/quality", "GET").h())
        assert.are.equal("failed", data.ret)
        assert.are.equal(200, ngx.status)
        assert.are.equal(g.quality_err, data.message)
    end)

    it("GET /geoip/config redacts live credentials", function()
        local data = json.decode(route("/geoip/config", "GET").h())
        assert.are.equal("(redacted)", data.data.api_key)
    end)

    it("PUT /geoip/config merges the section over the full config", function()
        ngx.req.get_body_data = function()
            return json.encode({ geodb_path = "/new/path.mmdb" })
        end
        local data = json.decode(route("/geoip/config", "PUT").h())
        assert.are.equal("success", data.ret)
        assert.are.equal("/new/path.mmdb", config_fake._saved.geoip.geodb_path)
    end)

    it("PUT /geoip/config maps a save failure to 500", function()
        config_fake._save_ok = false
        ngx.req.get_body_data = function() return json.encode({}) end
        local data = json.decode(route("/geoip/config", "PUT").h())
        assert.are.equal("failed", data.ret)
        assert.are.equal(500, ngx.status)
    end)

    it("GET /geoip/status reports updater state", function()
        local data = json.decode(route("/geoip/status", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal("2026-10", data.data.version)
    end)

    it("POST /geoip/update surfaces updater failures with their status", function()
        updater_fake._ok, updater_fake._err, updater_fake._status = false, "http 403", 403
        local data = json.decode(route("/geoip/update", "POST").h())
        assert.are.equal("failed", data.ret)
        assert.are.equal(403, ngx.status)
        assert.are.equal("http 403", data.message)
    end)
end)
