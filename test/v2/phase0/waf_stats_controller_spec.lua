-- -*- coding: utf-8 -*-
-- P2-7: direct tests for the waf_stats controller.
-- waf-rule-manager and api.helpers are bound at require time; core.ip_reputation
-- is required lazily in the hit-detail handler. The shared dict (vn_config)
-- carries the test-history ring, per-rule stats and recent-hit records.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.status = 200
_G.ngx.ctx = {}
_G.ngx.var = { arg_limit = nil, arg_ip = nil, arg_bucket = nil, arg_hours = nil }
_G.ngx.req = {
    read_body = function() end,
    get_body_data = function() return "" end,
}
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

local NOW = 1700000000

local wm = {
    _rules = {},
    _test_results = {},
    _hits = {},
    _hits_called = nil,
}
function wm.load_rules() return { rules = wm._rules } end
function wm.test_rule(_rule, _cases) return wm._test_results end
function wm.get_recent_hits(limit)
    wm._hits_called = limit
    return wm._hits
end

local helpers_fake = {}
function helpers_fake.is_valid_ip(ip)
    if type(ip) ~= "string" then return false end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    return tonumber(a) <= 255 and tonumber(b) <= 255
        and tonumber(c) <= 255 and tonumber(d) <= 255
end

local rep_fake = {}
function rep_fake.get_score(ip) return ip == "1.2.3.4" and 42 or 0 end
function rep_fake.is_flagged(ip) return ip == "1.2.3.4" end
function rep_fake.is_whitelisted(ip) return false end

local wm_orig = package.loaded["waf-rule-manager"]
local helpers_orig = package.loaded["api.helpers"]
package.loaded["waf-rule-manager"] = wm
package.loaded["api.helpers"] = helpers_fake

local controller = require "api.controllers.waf_stats"
local api = { routes = {} }
function api.register(m, p, h, a) api.routes[#api.routes + 1] = { m = m, p = p, h = h } end
controller.register(api)
local function route(path, method)
    for _, r in ipairs(api.routes) do
        if r.p == path and r.m == method then return r end
    end
    return nil
end
local function cfg() return ngx.shared.vn_config end

describe("WAF stats controller (P2-7)", function()
    before_each(function()
        cfg():flush_all()
        package.loaded["core.ip_reputation"] = rep_fake
        wm._rules = {
            { id = "r1", name = "SQLi", category = "sqli", severity = "high", enable = true },
            { id = "r2", name = "XSS", category = "xss", severity = "medium" },
        }
        wm._test_results = {}
        wm._hits = {}
        wm._hits_called = nil
        ngx.status = 200
        ngx.ctx = {}
        ngx.var.arg_limit = nil
        ngx.var.arg_ip = nil
        ngx.var.arg_bucket = nil
        ngx.var.arg_hours = nil
        ngx.req.get_body_data = function() return "" end
    end)
    after_each(function()
        package.loaded["core.ip_reputation"] = nil
        package.loaded["waf-rule-manager"] = wm_orig
        package.loaded["api.helpers"] = helpers_orig
    end)

    it("registers 10 routes", function()
        assert.are.equal(10, #api.routes)
    end)

    it("POST /waf/rules/test validates the request", function()
        local h = route("/waf/rules/test", "POST").h
        local d1 = json.decode(h())
        assert.are.equal(400, ngx.status)
        assert.are.equal("request body required", d1.message)
        ngx.req.get_body_data = function() return "{{bad" end
        assert.are.equal("invalid JSON", json.decode(h()).message)
        ngx.req.get_body_data = function() return json.encode({ rule = { name = "x" } }) end
        assert.are.equal("test_cases is required", json.decode(h()).message)
        ngx.req.get_body_data = function() return json.encode({ rule = { name = "x" }, test_cases = {} }) end
        assert.are.equal("test_cases is required", json.decode(h()).message)
        local many = {}
        for i = 1, 201 do many[i] = { name = "c" .. i } end
        ngx.req.get_body_data = function()
            return json.encode({ rule = { name = "x" }, test_cases = many })
        end
        assert.are.equal("test_cases exceeds max of 200", json.decode(h()).message)
    end)

    it("POST /waf/rules/test runs cases and records the history ring", function()
        wm._test_results = { { passed = true }, { passed = false }, { passed = true } }
        ngx.req.get_body_data = function()
            return json.encode({
                rule = { name = "probe" },
                test_cases = { { name = "a" }, { name = "b" }, { name = "c" } },
            })
        end
        local data = json.decode(route("/waf/rules/test", "POST").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(3, data.data.total)
        assert.are.equal(2, data.data.passed)
        assert.are.equal(1, data.data.failed)
        -- ring: one entry recorded, decodable
        local history = json.decode(route("/waf/test-history", "GET").h())
        assert.are.equal(1, #history.data)
        assert.are.equal("probe", history.data[1].rule_name)
        assert.are.equal(NOW, history.data[1].timestamp)
        -- DELETE clears the ring
        json.decode(route("/waf/test-history", "DELETE").h())
        history = json.decode(route("/waf/test-history", "GET").h())
        assert.are.equal(0, #history.data)
    end)

    it("GET /waf/stats aggregates rules and runtime stats", function()
        cfg():set("waf_rule_stats:r1", json.encode({ hit_count = 7, last_triggered = NOW - 3600 }))
        local today_key = "waf_rule_stats:r1:today:" .. os.date("!%Y%m%d", NOW)
        cfg():set(today_key, 3)
        local data = json.decode(route("/waf/stats", "GET").h())
        assert.are.equal(2, data.data.total_rules)
        assert.are.equal(2, data.data.enabled_rules) -- enable==nil counts as enabled
        assert.are.equal(7, data.data.total_hits)
        assert.are.equal(3, data.data.today_hits)
        assert.are.equal(1, data.data.by_category.sqli.rules)
        assert.are.equal(7, data.data.by_category.sqli.hits)
        assert.are.equal("r1", data.data.top_rules[1].id)
        assert.are.equal(7, data.data.top_rules[1].hits)
    end)

    it("GET /waf/stats/:id returns the rule's runtime stats", function()
        ngx.ctx.waf_rule_id = nil
        local d0 = json.decode(route("/waf/stats/:id", "GET").h())
        assert.are.equal(400, ngx.status)
        cfg():set("waf_rule_stats:r1", json.encode({ hit_count = 9, block_count = 4 }))
        ngx.ctx.waf_rule_id = "r1"
        local data = json.decode(route("/waf/stats/:id", "GET").h())
        assert.are.equal(9, data.data.hit_count)
        assert.are.equal(4, data.data.block_count)
    end)

    it("GET /waf/stats without a shared dict is an empty success", function()
        -- The daily-counter read (waf_stats.lua) used to 500 without
        -- ngx.shared.vn_config; like /waf/analytics it must return success
        -- with zero stats. (Setting ngx.shared = nil would crash the index
        -- itself; a plain empty table makes vn_config nil.)
        local saved = _G.ngx.shared
        _G.ngx.shared = {}
        local data = json.decode(route("/waf/stats", "GET").h())
        _G.ngx.shared = saved
        assert.are.equal("success", data.ret)
        assert.are.equal(2, data.data.total_rules)
        assert.are.equal(0, data.data.total_hits)
        assert.are.equal(0, data.data.today_hits)
    end)

    it("GET /waf/hits clamps the limit at 200", function()
        wm._hits = { { ip = "1.2.3.4" } }
        ngx.var.arg_limit = "5000"
        local data = json.decode(route("/waf/hits", "GET").h())
        assert.are.equal(1, #data.data)
        assert.are.equal(200, wm._hits_called)
    end)

    it("GET /waf/hits/by-ip filters the ring and resolves rule names", function()
        local d0 = json.decode(route("/waf/hits/by-ip", "GET").h())
        assert.are.equal(400, ngx.status)
        assert.are.equal("ip parameter required", d0.message)
        ngx.var.arg_ip = "999.1.1.1"
        assert.are.equal("invalid IP address", json.decode(route("/waf/hits/by-ip", "GET").h()).message)
        ngx.var.arg_ip = "1.2.3.4"
        cfg():set("waf_recent_hits:data:1", json.encode({ ip = "1.2.3.4", rule_id = "r1", timestamp = 100, action = "block" }))
        cfg():set("waf_recent_hits:data:2", json.encode({ ip = "5.6.7.8", rule_id = "r2", timestamp = 200, action = "block" }))
        local data = json.decode(route("/waf/hits/by-ip", "GET").h())
        assert.are.equal(1, #data.data)
        assert.are.equal("SQLi", data.data[1].rule_name)
        assert.are.equal(1, data.data[1].ring_idx)
    end)

    it("GET /waf/hits/:id returns 404 for a missing ring slot", function()
        ngx.ctx.waf_rule_id = "9"
        local data = json.decode(route("/waf/hits/:id", "GET").h())
        assert.are.equal(404, ngx.status)
        assert.are.equal("hit detail not found", data.message)
    end)

    it("GET /waf/hits/:id rejects a missing index and corrupted data", function()
        local d0 = json.decode(route("/waf/hits/:id", "GET").h())
        assert.are.equal(400, ngx.status)
        cfg():set("waf_recent_hits:data:1", "{{not json")
        ngx.ctx.waf_rule_id = "1"
        local d1 = json.decode(route("/waf/hits/:id", "GET").h())
        assert.are.equal(500, ngx.status)
        assert.are.equal("corrupted detail data", d1.message)
    end)

    it("GET /waf/hits/:id enriches with rule metadata and reputation", function()
        cfg():set("waf_recent_hits:data:1", json.encode({ ip = "1.2.3.4", rule_id = "r1", timestamp = 50, action = "block" }))
        cfg():set("waf_recent_hits:data:2", json.encode({ ip = "1.2.3.4", rule_id = "r2", timestamp = 60, action = "block" }))
        ngx.ctx.waf_rule_id = "1"
        local data = json.decode(route("/waf/hits/:id", "GET").h())
        assert.are.equal("SQLi", data.data.rule_name)
        assert.are.equal("sqli", data.data.rule_category)
        assert.are.equal(42, data.data.ip_score)
        assert.is_true(data.data.ip_flagged)
        assert.is_false(data.data.ip_whitelisted)
        assert.are.equal(2, data.data.ip_hit_count)
    end)

    it("GET /waf/timeline buckets block actions inside the window", function()
        local inside = NOW - 100          -- within the default 1-hour window
        cfg():set("waf_recent_hits:data:1", json.encode({ ip = "1.1.1.1", rule_id = "r1", timestamp = inside, action = "block" }))
        cfg():set("waf_recent_hits:data:2", json.encode({ ip = "1.1.1.1", rule_id = "r2", timestamp = inside, action = "log" }))
        cfg():set("waf_recent_hits:data:3", json.encode({ ip = "1.1.1.1", rule_id = "r1", timestamp = NOW - 7200, action = "block" }))
        local data = json.decode(route("/waf/timeline", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(12, #data.data.buckets)  -- 1h / 5min buckets
        -- categories come from the rule mapping, not the counted hits
        assert.are.equal(2, #data.data.categories)
        local catset = {}
        for _, c in ipairs(data.data.categories) do catset[c] = true end
        assert.is_true(catset.sqli)
        assert.is_true(catset.xss)
        -- only data:1 counts: bucket index floor(3500/300) = 11 -> last bucket
        assert.are.equal(1, data.data.buckets[12].counts.sqli)
        assert.is_nil(data.data.buckets[1].counts.sqli)
    end)

    it("GET /waf/analytics grades rules and detects dead ones", function()
        local today = os.date("!%Y%m%d")
        wm._rules = {
            { id = "r1", name = "always-blocks", enable = true, action = "block" },
            { id = "r2", name = "challenge", enable = true, action = "challenge" },
            { id = "r3", name = "stale", enable = false, _created = NOW - 40 * 86400 },
        }
        cfg():set("waf_rule_stats:r1", json.encode({ hit_count = 100, block_count = 100, last_triggered = NOW - 3600 }))
        cfg():set("waf_rule_stats:r2", json.encode({ hit_count = 10, block_count = 0, challenge_count = 10, last_triggered = NOW - 100 }))
        cfg():set("waf_rule_stats:r2:cpass:" .. today, 8)
        cfg():set("waf_rule_stats:r2:chal:" .. today, 10)
        local data = json.decode(route("/waf/analytics", "GET").h())
        assert.are.equal(3, #data.data.rules)
        assert.are.equal("A+", data.data.rules[1].grade)
        assert.are.equal("C", data.data.rules[2].grade)      -- 8/10 pass rate >= 0.8
        assert.are.equal("80%", data.data.rules[2].challenge_pass_rate)
        assert.are.equal(1, #data.data.dead_rules)
        assert.are.equal("r3", data.data.dead_rules[1].id)
    end)

    it("GET /waf/hits/by-ip survives a corrupted ring slot", function()
        ngx.var.arg_ip = "1.2.3.4"
        cfg():set("waf_recent_hits:data:1", "{{corrupted")
        cfg():set("waf_recent_hits:data:2", json.encode({ ip = "1.2.3.4", rule_id = "r1", timestamp = 200, action = "block" }))
        local data = json.decode(route("/waf/hits/by-ip", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(1, #data.data)
        assert.are.equal(2, data.data[1].ring_idx)
    end)

    it("GET /waf/test-history skips a corrupted ring slot", function()
        cfg():set("waf_test_history:idx", 1)
        cfg():set("waf_test_history:data:1", "{{corrupted")
        cfg():set("waf_test_history:data:2", json.encode({ rule_name = "ok", total = 1, timestamp = NOW }))
        local data = json.decode(route("/waf/test-history", "GET").h())
        assert.are.equal(1, #data.data)
        assert.are.equal("ok", data.data[1].rule_name)
    end)

    it("GET /waf/analytics treats a corrupted stats entry as empty", function()
        cfg():set("waf_rule_stats:r1", "{{corrupted")
        local data = json.decode(route("/waf/analytics", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(0, data.data.rules[1].hits)
        assert.are.equal("N/A", data.data.rules[1].grade)
    end)

    it("GET /waf/analytics without a shared dict is an empty success", function()
        -- A plain table (no dict metatable): .vn_config is nil, which is the
        -- guard path. (Setting ngx.shared = nil would crash the index itself.)
        local saved = _G.ngx.shared
        _G.ngx.shared = {}
        local data = json.decode(route("/waf/analytics", "GET").h())
        _G.ngx.shared = saved
        assert.are.equal("success", data.ret)
        assert.are.equal(0, #data.data.rules)
        assert.are.equal(0, #data.data.dead_rules)
    end)
end)
