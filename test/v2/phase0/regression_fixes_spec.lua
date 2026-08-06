-- -*- coding: utf-8 -*-
-- Regression tests for the 15-issue audit fixes (Lua-side, cosocket-free).

local function setup_ngx()
    if not _G.ngx then _G.ngx = {} end
    local ngx = _G.ngx
    function ngx.log() end
    ngx.WARN = 6; ngx.ERR = 5; ngx.INFO = 7
    ngx.time = function() return 1700000000 end
    ngx.sleep = function() end
    ngx.md5 = function(s) return "h" .. tostring(s):sub(1, 8) end
    ngx.crc32_short = function() return 0 end
    ngx.worker = { id = function() return 0 end }
    ngx.shared = setmetatable({}, {
        __index = function(_, name)
            ngx._stores = ngx._stores or {}
            ngx._counters = ngx._counters or {}
            ngx._store_keys = ngx._store_keys or {}
            if not ngx._stores[name] then
                ngx._stores[name] = {}
                ngx._counters[name] = {}
                ngx._store_keys[name] = {}
            end
            local st = ngx._stores[name]
            local cnt = ngx._counters[name]
            local order = ngx._store_keys[name]
            local function insert(k)
                if not order[k] then order[k] = true; table.insert(order, k) end
            end
            return {
                get = function(_, k) return st[k] end,
                set = function(_, k, v)
                    st[k] = v; insert(k); return true
                end,
                add = function(_, k, v)
                    if st[k] then return false, "exists" end
                    st[k] = v; insert(k); return true, nil
                end,
                incr = function(_, k, d, i)
                    if st[k] == nil then st[k] = (i or 0); insert(k) end
                    st[k] = st[k] + d; return st[k], nil
                end,
                delete = function(_, k) st[k] = nil; cnt[k] = nil; order[k] = nil end,
                flush_all = function()
                    for k in pairs(st) do st[k] = nil end
                    for k in pairs(cnt) do cnt[k] = nil end
                    for k in pairs(order) do order[k] = nil end
                end,
                get_keys = function(_, max)
                    local out = {}
                    local o = ngx._store_keys[name] or {}
                    for k = 1, #o do
                        if #out >= max then break end
                        out[#out + 1] = o[k]
                    end
                    return out
                end,
            }
        end,
    })
    ngx._keys = {}
    ngx._store_keys = ngx._store_keys or {}
    package.preload["bit"] = function()
        local m = {}
        function m.band(a, b)
            local r = 0
            local place = 1
            while a > 0 and b > 0 do
                if (a % 2 == 1) and (b % 2 == 1) then r = r + place end
                a = math.floor(a / 2); b = math.floor(b / 2); place = place * 2
            end
            return r
        end
        return m
    end
end

setup_ngx()

package.path = "verynginx/?.lua;" .. package.path

describe("#7 metrics export not truncated by get_keys(1000) cap", function()
    before_each(function()
        package.loaded["core.metrics"] = nil
        ngx.shared.metrics:flush_all()
        local m = require "core.metrics"
        m.init()
    end)

    it("exports every metric key via the maintained index", function()
        local metrics = require "core.metrics"
        -- Simulate a large rule set: 1200 gauge keys (well past the ~1024 cap).
        for i = 1, 1200 do
            metrics.gauge("waf_rule_hits_total", i, { rule_id = "r" .. i,
                category = "scanner", action = "block" })
        end
        local buf = metrics.export_prometheus()
        assert.truthy(buf)
        -- Count emitted samples (label order from pairs() is non-deterministic,
        -- so count by metric-name prefix only).
        local count = select(2, buf:gsub("waf_rule_hits_total{", ""))
        assert.are.equal(1200, count)
        -- The static HELP/TYPE line for the metric must be present.
        assert.truthy(buf:find("waf_rule_hits_total", 1, true))
    end)
end)

describe("ip_reputation.validate_whitelist_entry (#14)", function()
    it("accepts a bare IPv4", function()
        package.loaded["core.ip_reputation"] = nil
        local rep = require "core.ip_reputation"
        assert.is_true(rep.validate_whitelist_entry("1.2.3.4"))
    end)
    it("accepts a clean IPv4 CIDR", function()
        local rep = require "core.ip_reputation"
        assert.is_true(rep.validate_whitelist_entry("192.168.1.0/24"))
    end)
    it("rejects a CIDR with host bits set", function()
        local rep = require "core.ip_reputation"
        assert.is_false(rep.validate_whitelist_entry("192.168.1.5/24"))
    end)
    it("rejects garbage / out-of-range", function()
        local rep = require "core.ip_reputation"
        assert.is_false(rep.validate_whitelist_entry("300.1.2.3"))
        assert.is_false(rep.validate_whitelist_entry("not-an-ip"))
        assert.is_false(rep.validate_whitelist_entry(""))
        assert.is_false(rep.validate_whitelist_entry("0.0.0.0/0"))
        assert.is_true(rep.validate_whitelist_entry("10.0.0.0/32"))
    end)
end)

describe("#18 frequency_templates.apply() validates overrides", function()
    it("rejects unknown override fields", function()
        package.loaded["core.frequency_templates"] = nil
        local tpl = require "core.frequency_templates"
        local rule, err = tpl.apply("login_bruteforce", { evil = "payload" })
        assert.is_nil(rule)
        assert.truthy(err:find("unsupported override"))
    end)
    it("rejects wrong-typed overrides", function()
        local tpl = require "core.frequency_templates"
        local rule, err = tpl.apply("login_bruteforce", { limit = "one" })
        assert.is_nil(rule)
        assert.truthy(err:find("must be number"))
    end)
    it("rejects out-of-range overrides", function()
        local tpl = require "core.frequency_templates"
        assert.is_nil((tpl.apply("login_bruteforce", { window = 0 })))
        assert.is_nil((tpl.apply("login_bruteforce", { code = 99 })))
        assert.is_nil((tpl.apply("login_bruteforce", { matcherJson = "{not-json" })))
    end)
    it("still applies valid overrides", function()
        local tpl = require "core.frequency_templates"
        local rule = tpl.apply("login_bruteforce", { limit = 10, window = 120 })
        assert.truthy(rule)
        assert.are.equal(10, rule.limit)
        assert.are.equal(120, rule.window)
    end)
end)

describe("#17 frequency limiter user dimension falls back to IP", function()
    it("unauthenticated requests do not share an anonymous bucket", function()
        package.loaded["plugin.frequency_limit.limiter"] = nil
        local lim = require "plugin.frequency_limit.limiter"
        local ctx = {
            request = { remote_addr = "203.0.113.7", uri = "/x", host = "h" },
            get_data = function() return nil end,
        }
        local v = lim._dimension_value("user", ctx)
        assert.truthy(v)
        assert.is_not.equal("anonymous", v)
        assert.truthy(v:find("203.0.113.7", 1, true))
    end)
    it("authenticated requests keep the username", function()
        local lim = require "plugin.frequency_limit.limiter"
        local ctx = {
            request = { remote_addr = "203.0.113.7" },
            get_data = function() return "alice" end,
        }
        local v = lim._dimension_value("user", ctx)
        assert.are.equal("alice", v)
    end)
end)

describe("#8 recommender only analyzes blocked hits", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        package.loaded["core.waf_recommender"] = nil
        package.loaded["core.config"] = {
            waf_recommender = {
                enabled = true, min_hits = 1, window_size = 3600, min_patterns = 1,
            },
        }
    end)
    it("skips challenge hits and keeps block hits", function()
        local json = require "dkjson"
        local now = ngx.time()
        -- 2 challenge hits on /login: must be ignored.
        ngx.shared.vn_config:set("waf_recent_hits:data:1",
            json.encode({ action = "challenge", uri = "/login", timestamp = now, ip = "1.1.1.1" }))
        ngx.shared.vn_config:set("waf_recent_hits:data:2",
            json.encode({ action = "challenge", uri = "/login", timestamp = now, ip = "1.1.1.2" }))
        -- 2 block hits on /etc/passwd: must generate a suggestion.
        ngx.shared.vn_config:set("waf_recent_hits:data:3",
            json.encode({ action = "block", uri = "/etc/passwd", timestamp = now, ip = "2.2.2.2" }))
        ngx.shared.vn_config:set("waf_recent_hits:data:4",
            json.encode({ action = "block", uri = "/etc/passwd", timestamp = now, ip = "2.2.2.3" }))
        local rec = require "core.waf_recommender"
        rec.analyze()
        local items = rec.list()
        assert.are.equal(1, #items)
        assert.truthy(items[1].pattern:find("/etc/passwd", 1, true))
        assert.truthy(items[1].pattern:find("/login") == nil)
    end)
end)