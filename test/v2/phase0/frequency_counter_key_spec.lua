-- -*- coding: utf-8 -*-
-- Tests for the Frequency Counter Key (single namespace) - Phase 0
--
-- Self-contained: uses real config module + frequency limiter + encoding.
--
-- There used to be two namespaces (a raw "fl:v1:..." one and a length-prefixed
-- "fl:v2:count:..." one) with a runtime switch. These tests pin the single
-- namespace that replaced them, and the property the switch never bought:
-- two dimension splits must not land on the same key.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

-- Minimal ngx stub
if not ngx then ngx = {} end
function ngx.log() end
ngx.WARN = 6; ngx.ERR = 5
ngx.time = function() return 1700000000 end
ngx.md5 = function(s) return "x" end
ngx.shared = setmetatable({}, {
    __index = function(_, name)
        ngx._stores = ngx._stores or {}
        ngx._counters = ngx._counters or {}
        if not ngx._stores[name] then ngx._stores[name] = {}; ngx._counters[name] = {} end
        local st = ngx._stores[name]
        local cnt = ngx._counters[name]
        return {
            get = function(_, key) return st[key] end,
            set = function(_, key, val) st[key] = val; return true end,
            add = function(_, key, val) if st[key] then return false end; st[key] = val; return true end,
            incr = function(_, key, delta, init) cnt[key] = (cnt[key] or (init or 0)) + delta; st[key] = cnt[key]; return cnt[key] end,
            delete = function(_, key) st[key] = nil; cnt[key] = nil end,
            expire = function(_, key, ttl) end,
        }
    end,
})

package.preload["bit"] = function() return { band = function() return 0 end } end

local ip_enc = require "core.kernel_blocking.ip_encoding"
local limiter = require "plugin.frequency_limit.limiter"

describe("IP encoding", function()
    it("canonical_ip strips leading zeros from IPv4", function()
        assert.are.equal("192.168.1.1", ip_enc.canonical_ip("192.168.001.001"))
    end)

    it("canonical_ip leaves valid IPv4 unchanged", function()
        assert.are.equal("10.0.0.1", ip_enc.canonical_ip("10.0.0.1"))
    end)

    it("canonical_ip folds an IPv4-mapped IPv6 into the IPv4", function()
        assert.are.equal("1.2.3.4", ip_enc.canonical_ip("::ffff:1.2.3.4"))
    end)

    it("encode_dimension uses length prefix", function()
        local enc = ip_enc.encode_dimension("test")
        -- Length byte + "test" (4 chars)
        assert.are.equal(5, #enc)
    end)

    it("encode_dimension handles colon-containing values safely", function()
        -- A value containing ':' would collide with the separator; the length
        -- prefix makes the split unambiguous.
        local enc = ip_enc.encode_dimension("a:b:c")
        assert.are.equal(6, #enc)
    end)

    it("count_key has the single namespace prefix", function()
        local key = ip_enc.count_key(ip_enc.encode_rule_id("rule_1"),
                                     ip_enc.encode_dimension("10.0.0.1"))
        assert.truthy(key:find("^fl:count:"))
        assert.falsy(key:find("v1", 1, true))
        assert.falsy(key:find("v2", 1, true))
    end)

    it("violation_key has the single namespace prefix", function()
        local key = ip_enc.violation_key(ip_enc.encode_rule_id("rule_1"),
                                         "10.0.0.1", 28333333)
        assert.truthy(key:find("^fl:cc:violation:"))
        assert.truthy(key:find("10.0.0.1:28333333", 1, true))
    end)

    it("the rule-less counter key cannot collide with an id-bearing one", function()
        local noid = ip_enc.count_key_noid(ip_enc.encode_dimension("10.0.0.1"))
        local withid = ip_enc.count_key(ip_enc.encode_rule_id("legacy"),
                                        ip_enc.encode_dimension("10.0.0.1"))
        assert.are_not.equal(noid, withid)
    end)
end)

describe("limiter build_key", function()
    it("returns length-prefixed dimension value", function()
        local ctx = { request = { remote_addr = "192.168.1.1" } }
        local enc = limiter.build_key("ip", ctx)
        -- Should be length-prefixed "192.168.1.1" (not include "fl:" or "ip:")
        assert.falsy(enc:find("^fl:"))
        assert.falsy(enc:find("^ip:"))
    end)

    it("is deterministic", function()
        local ctx = { request = { remote_addr = "192.168.1.1" } }
        assert.are.equal(limiter.build_key("ip", ctx), limiter.build_key("ip", ctx))
    end)

    -- Two rules on the same dimension used to share ONE counter, and the
    -- plugin increments once per matching rule, so a burst against two
    -- ip-keyed rules counted double against both thresholds. The counter must
    -- stay namespaced per rule id.
    it("keeps the per-rule isolation through the caller", function()
        local ctx = { request = { remote_addr = "10.0.0.1" } }
        local dim = limiter.build_key("ip", ctx)
        local a = ip_enc.count_key(ip_enc.encode_rule_id("freq_global_cc"), dim)
        local b = ip_enc.count_key(ip_enc.encode_rule_id("freq_burst_cc"), dim)
        assert.are_not.equal(a, b)
    end)

    -- The raw encoding could not tell two dimension splits apart. With an
    -- IPv6 address the host dimension and the ip dimension both carry ':',
    -- so "host=a + ip=2001:db8::1" and "host=a:2001 + ip=db8::1" produced the
    -- same key and shared one counter.
    it("two dimension splits do not land on the same key", function()
        local function ctx_of(host, ip)
            return { request = { remote_addr = ip, uri = "/x", host = host } }
        end
        local a = ip_enc.count_key(ip_enc.encode_rule_id("r1"),
            limiter.build_key({"host","ip"}, ctx_of("a", "2001:db8::1")))
        local b = ip_enc.count_key(ip_enc.encode_rule_id("r1"),
            limiter.build_key({"host","ip"}, ctx_of("a:2001", "db8::1")))
        assert.are_not.equal(a, b)
    end)

    it("normalises the host dimension", function()
        -- The raw Host header carries the port and the original case; an
        -- unnormalised value splits one visitor into several buckets.
        local a = limiter.build_key("host", { request = { host = "Example.COM:8080" } })
        local b = limiter.build_key("host", { request = { host = "example.com:8080" } })
        assert.are.equal(a, b)
    end)
end)
