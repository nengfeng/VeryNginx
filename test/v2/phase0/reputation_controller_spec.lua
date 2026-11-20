-- -*- coding: utf-8 -*-
-- P2-7: direct tests for the reputation controller.
-- core.ip_reputation and core.crawler_ranges are required lazily inside the
-- handlers; api.helpers is bound at require time, so its mock must be in
-- place before the controller loads.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.status = 200
_G.ngx.ctx = {}
_G.ngx.var = { arg_ip = nil }
_G.ngx.req = { read_body = function() end, get_body_data = function() return "" end }
_G.ngx.worker = { id = function() return 0 end }

local json = require "dkjson"

local helpers_fake = {}
function helpers_fake.is_valid_ip(ip)
    if type(ip) ~= "string" then return false end
    if ip:find(":") then
        -- crude v6 check: at least one hex group before a colon
        return ip:match("^(%x+):") ~= nil
    end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    return tonumber(a) <= 255 and tonumber(b) <= 255
        and tonumber(c) <= 255 and tonumber(d) <= 255
end
local helpers_orig = package.loaded["api.helpers"]
package.loaded["api.helpers"] = helpers_fake

local rep_state = { flagged = {}, whitelist = {}, score = {}, reasons = {}, metas = {} }
local _meta = {}
local function e_meta(ip) return _meta[ip] or {} end

local rep_fake = {}
function rep_fake.get_stats()
    local n = 0
    for _ in pairs(rep_state.flagged) do n = n + 1 end
    return { flagged = n }
end
function rep_fake.list_flagged()
    local out = {}
    for ip in pairs(rep_state.flagged or {}) do
        local e = { ip = ip }
        for k, v in pairs(e_meta(ip)) do e[k] = v end
        out[#out + 1] = e
    end
    return out
end
function rep_fake.list_whitelist() return rep_state.whitelist or {} end
function rep_fake.get_score(ip) return (rep_state.score[ip] or 0) end
function rep_fake.is_flagged(ip) return rep_state.flagged[ip] ~= nil end
function rep_fake.has_pending() return false end
function rep_fake.is_whitelisted(ip) return (rep_state.whitelist or {})[ip] == true end
function rep_fake.score_explain() return { points = 0 } end
function rep_fake.get_signal_breakdown() return {} end
function rep_fake.get_flag_reason(ip) return rep_state.reasons[ip] end
function rep_fake.get_flag_meta(ip) return rep_state.metas[ip] end
function rep_fake.clear_ip(ip)
    rep_state.flagged[ip] = nil
    rep_state.score[ip] = nil
end
function rep_fake.validate_whitelist_entry(entry)
    -- Mirror the real module's contract: a plain IP must pass is_valid_ip;
    -- a CIDR (contains "/") must start with a digit or a masked host.
    if type(entry) == "string" and entry:find("/") then
        return entry:match("^%d") ~= nil
    end
    return helpers_fake.is_valid_ip(entry)
end
function rep_fake.add_whitelist(ip)
    rep_state.whitelist = rep_state.whitelist or {}
    rep_state.whitelist[ip] = true
end
function rep_fake.remove_whitelist(ip)
    if rep_state.whitelist then rep_state.whitelist[ip] = nil end
end
function rep_fake.persist() end

local crawler_fake = { _apply_ok = true }
function crawler_fake.status() return { count = 1200, last_fetch = 1700000000 } end
function crawler_fake.apply()
    return { ok = crawler_fake._apply_ok, applied = 3 }
end
function crawler_fake.fetch()
    return { { vendor = "A", ok = true, ranges = { "1.2.3.4/32" } },
             { vendor = "B", ok = true, ranges = { "9.9.9.9/32" } } }
end

local rep_orig = package.loaded["core.ip_reputation"]
local crawler_orig = package.loaded["core.crawler_ranges"]

local controller = require "api.controllers.reputation"
local api = { routes = {} }
function api.register(m, p, h, a) api.routes[#api.routes + 1] = { m = m, p = p, h = h } end
controller.register(api)
local function route(path, method)
    for _, r in ipairs(api.routes) do
        if r.p == path and r.m == method then return r end
    end
    return nil
end

describe("Reputation controller (P2-7)", function()
    before_each(function()
        for k in pairs(rep_state) do rep_state[k] = nil end
        rep_state.flagged = {}; rep_state.whitelist = {}
        rep_state.score = {}; rep_state.reasons = {}; rep_state.metas = {}
        for k in pairs(_meta) do _meta[k] = nil end
        crawler_fake._apply_ok = true
        package.loaded["core.ip_reputation"] = rep_fake
        package.loaded["core.crawler_ranges"] = crawler_fake
        ngx.status = 200
        ngx.ctx = {}
        ngx.var.arg_ip = nil
        ngx.req.get_body_data = function() return "" end
    end)
    after_each(function()
        package.loaded["core.ip_reputation"] = rep_orig
        package.loaded["core.crawler_ranges"] = crawler_orig
        package.loaded["api.helpers"] = helpers_orig
    end)

    it("registers 10 routes", function()
        assert.are.equal(10, #api.routes)
    end)

    it("GET /reputation/flagged carries per-ip metadata", function()
        rep_state.flagged["203.0.113.1"] = true
        _meta["203.0.113.1"] = { reason = "scanner-ua" }
        local data = json.decode(route("/reputation/flagged", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(1, #data.data)
        assert.are.equal("203.0.113.1", data.data[1].ip)
        assert.are.equal("scanner-ua", data.data[1].reason)
    end)

    it("GET /reputation/flagged normalises a missing reason to json.null", function()
        rep_state.flagged["203.0.113.2"] = true
        -- Check the RAW payload: json.null decodes back to a missing key, so
        -- the key's presence is only visible in the encoded string.
        local raw = route("/reputation/flagged", "GET").h()
        local data = json.decode(raw)
        assert.are.equal(1, #data.data)
        assert.are.equal("203.0.113.2", data.data[1].ip)
        assert.truthy(raw:find('"reason"'))
    end)

    it("GET /reputation/stats reports counts", function()
        rep_state.flagged["1.1.1.1"] = true
        local data = json.decode(route("/reputation/stats", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(1, data.data.flagged)
    end)

    it("GET /reputation/score requires and validates the ip", function()
        local d1 = json.decode(route("/reputation/score", "GET").h())
        assert.are.equal(400, ngx.status)
        ngx.var.arg_ip = "not-an-ip"
        local d2 = json.decode(route("/reputation/score", "GET").h())
        assert.are.equal("invalid ip format", d2.message)
        ngx.var.arg_ip = "203.0.113.9"
        rep_state.score["203.0.113.9"] = 42
        local d3 = json.decode(route("/reputation/score", "GET").h())
        assert.are.equal("success", d3.ret)
        assert.are.equal(42, d3.data.score)
        assert.is_table(d3.data.explain)
    end)

    it("POST /reputation/clear validates the ip", function()
        ngx.var.arg_ip = "999.1.1.1"
        local data = json.decode(route("/reputation/clear", "POST").h())
        assert.are.equal("failed", data.ret)
        assert.are.equal(400, ngx.status)
        ngx.var.arg_ip = "203.0.113.7"
        rep_state.flagged["203.0.113.7"] = true
        local ok = json.decode(route("/reputation/clear", "POST").h())
        assert.are.equal("success", ok.ret)
        assert.is_nil(rep_state.flagged["203.0.113.7"])
    end)

    it("POST /reputation/whitelist accepts a body when the arg is absent", function()
        ngx.req.get_body_data = function() return json.encode({ ip = "10.1.1.1" }) end
        local data = json.decode(route("/reputation/whitelist", "POST").h())
        assert.are.equal("success", data.ret)
        assert.is_true(rep_state.whitelist["10.1.1.1"])
    end)

    it("POST /reputation/whitelist rejects an invalid ip or cidr", function()
        ngx.var.arg_ip = "999.1.1.1"
        local data = json.decode(route("/reputation/whitelist", "POST").h())
        assert.are.equal("failed", data.ret)
        assert.are.equal(400, ngx.status)
    end)

    it("POST /reputation/whitelist accepts a CIDR entry", function()
        ngx.var.arg_ip = "10.2.0.0/16"
        local data = json.decode(route("/reputation/whitelist", "POST").h())
        assert.are.equal("success", data.ret)
        assert.is_true(rep_state.whitelist["10.2.0.0/16"])
    end)

    it("DELETE /reputation/whitelist mirrors CIDR validation", function()
        rep_state.whitelist["10.2.0.0/16"] = true
        ngx.var.arg_ip = "10.2.0.0/16"
        local data = json.decode(route("/reputation/whitelist", "DELETE").h())
        assert.are.equal("success", data.ret)
        assert.is_nil(rep_state.whitelist["10.2.0.0/16"])
    end)

    it("POST /reputation/persist reports the worker that wrote", function()
        local data = json.decode(route("/reputation/persist", "POST").h())
        assert.are.equal("success", data.ret)
        assert.is_true(data.persisted)
        assert.are.equal(0, data.worker)
    end)

    it("GET /reputation/crawler/sources reports range status", function()
        local data = json.decode(route("/reputation/crawler/sources", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(1200, data.data.count)
    end)

    it("POST /reputation/crawler/fetch previews without applying", function()
        ngx.req.get_body_data = function() return json.encode({ apply = false }) end
        local data = json.decode(route("/reputation/crawler/fetch", "POST").h())
        assert.are.equal("success", data.ret)
        assert.is_true(data.data.preview)
        assert.is_nil(data.data.results[1].ranges, "preview strips ranges")
    end)

    it("POST /reputation/crawler/fetch applies by default", function()
        ngx.req.get_body_data = function() return "" end
        local data = json.decode(route("/reputation/crawler/fetch", "POST").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(3, data.data.applied)
    end)

    it("POST /reputation/crawler/fetch maps an apply failure to 502", function()
        crawler_fake._apply_ok = false
        ngx.req.get_body_data = function() return "" end
        local data = json.decode(route("/reputation/crawler/fetch", "POST").h())
        assert.are.equal("failed", data.ret)
        assert.are.equal(502, ngx.status)
    end)
end)
