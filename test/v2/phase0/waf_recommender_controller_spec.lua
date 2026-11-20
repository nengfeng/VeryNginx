-- -*- coding: utf-8 -*-
-- P2-7: direct tests for the waf_recommender controller.
-- The controller is a thin wrapper over core.waf_recommender; we inject a
-- fake for that module in before_each and restore it in after_each so no
-- later spec file in the shared busted process is poisoned.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.status = 200
_G.ngx.ctx = {}

local json = require "dkjson"

local rec_calls = {}
local rec_fake = { _items = {} }
function rec_fake.list()
    local out = {}
    for _, v in pairs(rec_fake._items) do out[#out + 1] = v end
    table.sort(out, function(a, b) return a.id < b.id end)
    return out
end
function rec_fake.apply(id)
    rec_calls.apply = (rec_calls.apply or 0) + 1
    if id == "bad" then return false, "recommendation not found" end
    local it = rec_fake._items[id]
    it.status = "applied"
    return true, nil
end
function rec_fake.get(id) return rec_fake._items[id] end
function rec_fake.update_status(id, status) rec_fake._items[id].status = status end
function rec_fake.analyze() return 3 end
function rec_fake.get_stats() return { total = 5, pending = 2 } end

local controller = require "api.controllers.waf_recommender"
local api = { routes = {} }
function api.register(m, p, h, a) api.routes[#api.routes + 1] = { m = m, p = p, h = h } end
controller.register(api)
local function route(path, method)
    for _, r in ipairs(api.routes) do
        if r.p == path and r.m == method then return r end
    end
    return nil
end

describe("WAF recommender controller (P2-7)", function()
    before_each(function()
        package.loaded["core.waf_recommender"] = rec_fake
        for k in pairs(rec_fake._items) do rec_fake._items[k] = nil end
        rec_fake._items["r1"] = { id = "r1", status = "pending", name = "block /etc" }
        rec_fake._items["r2"] = { id = "r2", status = "pending", name = "rate limit" }
        ngx.status = 200
        ngx.ctx = {}
    end)
    after_each(function()
        -- Clean up so no later spec file in the shared busted process sees
        -- the fake (AGENTS 9.3); the next before_each re-injects it.
        package.loaded["core.waf_recommender"] = nil
    end)

    it("registers 5 routes", function()
        assert.are.equal(5, #api.routes)
    end)

    it("GET /waf/recommendations lists pending", function()
        local data = json.decode(route("/waf/recommendations", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(2, #data.data)
    end)

    it("POST /waf/recommendations/:id/apply requires an id", function()
        local data = json.decode(route("/waf/recommendations/:id/apply", "POST").h())
        assert.are.equal("failed", data.ret)
        assert.are.equal(400, ngx.status)
        assert.are.equal("recommendation id required", data.message)
    end)

    it("POST apply on a missing id returns 400", function()
        ngx.ctx.waf_rule_id = "bad"
        local data = json.decode(route("/waf/recommendations/:id/apply", "POST").h())
        assert.are.equal("failed", data.ret)
        assert.are.equal(400, ngx.status)
    end)

    it("POST apply on a valid id marks it applied", function()
        ngx.ctx.waf_rule_id = "r1"
        local data = json.decode(route("/waf/recommendations/:id/apply", "POST").h())
        assert.are.equal("success", data.ret)
        assert.are.equal("applied", data.data.status)
    end)

    it("POST dismiss marks dismissed", function()
        ngx.ctx.waf_rule_id = "r2"
        local data = json.decode(route("/waf/recommendations/:id/dismiss", "POST").h())
        assert.are.equal("success", data.ret)
        assert.are.equal("dismissed", rec_fake._items["r2"].status)
    end)

    it("POST analyze reports the new recommendation count", function()
        local data = json.decode(route("/waf/recommendations/analyze", "POST").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(3, data.data.new_recommendations)
    end)

    it("GET stats returns the recommender stats", function()
        local data = json.decode(route("/waf/recommendations/stats", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(5, data.data.total)
    end)
end)
