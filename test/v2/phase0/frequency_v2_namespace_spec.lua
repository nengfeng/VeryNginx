-- -*- coding: utf-8 -*-
-- Tests for Frequency Counter Key v2 Namespace (Phase 0)
--
-- Self-contained: uses real config module + frequency limiter + encoding.

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

    it("encode_dimension uses length prefix", function()
        local enc = ip_enc.encode_dimension("test")
        -- Length byte + "test" (4 chars)
        assert.are.equal(5, #enc)
    end)

    it("encode_dimension handles colon-containing values safely", function()
        -- A value containing ':' would collide with v1 separator; v2 uses length-prefix
        local enc = ip_enc.encode_dimension("a:b:c")
        -- Length byte (3) + "a:b:c"
        assert.are.equal(6, #enc)
    end)

    it("v2_count_key has correct format", function()
        local key = ip_enc.v2_count_key("rule_1", ip_enc.encode_dimension("10.0.0.1"))
        assert.truthy(key:find("^fl:v2:count:"))
    end)

    it("v2_violation_key has correct format", function()
        local key = ip_enc.v2_violation_key("rule_1", "10.0.0.1", 28333333)
        assert.truthy(key:find("^fl:v2:kernel:violation:rule_1:10.0.0.1:28333333$"))
    end)
end)

describe("limiter v2 build_key_v2", function()
    it("returns length-prefixed dimension value", function()
        local ctx = { request = { remote_addr = "192.168.1.1" } }
        local enc = limiter.build_key_v2("ip", ctx)
        -- Should be length-prefixed "192.168.1.1" (not include "fl:" or "ip:")
        assert.falsy(enc:find("^fl:"))
        assert.falsy(enc:find("^ip:"))
    end)

    it("returns full key with v1 build_key", function()
        local ctx = { request = { remote_addr = "10.0.0.1" } }
        local key = limiter.build_key("ip", ctx)
        assert.truthy(key:find("^fl:ip:10.0.0.1"))
    end)

    it("v2 key for ip dimension is deterministic", function()
        local ctx = { request = { remote_addr = "192.168.1.1" } }
        local enc1 = limiter.build_key_v2("ip", ctx)
        local enc2 = limiter.build_key_v2("ip", ctx)
        assert.are.equal(enc1, enc2)
    end)

    it("v1 and v2 produce different formats for same input", function()
        local ctx = { request = { remote_addr = "10.0.0.1" } }
        local v1 = limiter.build_key("ip", ctx)
        local v2 = limiter.build_key_v2("ip", ctx)
        assert.are_not.equal(v1, v2)
    end)
end)
