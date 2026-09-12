-- -*- coding: utf-8 -*-
-- Tests for core/ip_quality: response parsing, ip_type classification,
-- cache hit / negative cache / reserved-range short-circuit (all without
-- network — resty.http is mocked and asserts when it must NOT be called).

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5
_G.ngx.time = function() return 1700000000 end
_G.ngx.now = function() return 1700000000 end

_G.ngx.shared = setmetatable({_cache = {}}, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v) st[k] = v; return true, nil end,
                add = function(_, k, v) if st[k] then return false, "exists" end; st[k] = v; return true, nil end,
                delete = function(_, k) st[k] = nil end,
            }
        end
        return t._cache[name]
    end,
})

-- Mock resty.http BEFORE the module loads. request_uri records every call
-- so specs can assert the fetcher ran (or did not).
local http_calls = {}
local canned_response = nil  -- {status=..., body=...} or "throw"
package.preload["resty.http"] = function()
    return {
        new = function()
            return {
                set_timeout = function() end,
                request_uri = function(self, url, opts)
                    http_calls[#http_calls + 1] = url
                    if canned_response == "throw" then error("network down") end
                    if canned_response then return canned_response end
                    return { status = 500, body = "unexpected" }
                end,
            }
        end,
    }
end

local function setup()
    http_calls = {}
    canned_response = nil
    _G.ngx.shared.vn_config:flush_all()
    package.loaded["core.ip_quality"] = nil
    return require "core.ip_quality"
end

describe("ip_quality.parse_response", function()
    local ipq
    before_each(function() ipq = setup() end)

    it("parses a success response and classifies ip_type", function()
        local e = ipq.parse_response([[{"status":"success","country":"United States",
            "countryCode":"US","regionName":"Virginia","city":"Ashburn","zip":"20149",
            "lat":39.03,"lon":-77.5,"timezone":"America/New_York","isp":"Google LLC",
            "org":"Google Public DNS","as":"AS15169 Google LLC","asname":"GOOGLE",
            "reverse":"dns.google","proxy":false,"hosting":true,"mobile":false,
            "query":"8.8.8.8"}]])
        assert.is_nil(e.reserved)
        assert.are.equal("Google LLC", e.isp)
        assert.are.equal("AS15169 Google LLC", e.as)
        assert.are.equal("dns.google", e.reverse)
        assert.are.equal("hosting", e.ip_type)
        assert.is_false(e.proxy)
    end)

    it("classifies proxy over hosting when both flags are set", function()
        local e = ipq.parse_response([[{"status":"success","proxy":true,
            "hosting":true,"mobile":false,"query":"1.2.3.4"}]])
        assert.are.equal("proxy", e.ip_type)
    end)

    it("classifies mobile and residential", function()
        local e1 = ipq.parse_response([[{"status":"success","mobile":true,"query":"1.2.3.4"}]])
        assert.are.equal("mobile", e1.ip_type)
        local e2 = ipq.parse_response([[{"status":"success","query":"1.2.3.4"}]])
        assert.are.equal("residential", e2.ip_type)
    end)

    it("returns the API failure message (private range etc.)", function()
        local e, err = ipq.parse_response([[{"status":"fail","message":"private range",
            "query":"192.168.1.1"}]])
        assert.is_nil(e)
        assert.are.equal("private range", err)
    end)

    it("rejects garbage bodies", function()
        local e, err = ipq.parse_response("<html>502 Bad Gateway</html>")
        assert.is_nil(e)
        assert.truthy(err:find("invalid JSON", 1, true))
    end)
end)

describe("ip_quality.lookup caching", function()
    local ipq
    before_each(function()
        ipq = setup()
        canned_response = { status = 200, body =
            [[{"status":"success","isp":"Test ISP","hosting":true,"query":"8.8.8.8"}]] }
    end)

    it("fetches, caches and returns the entry on a miss", function()
        local e = ipq.lookup("8.8.8.8")
        assert.are.equal(1, #http_calls)
        assert.are.equal("Test ISP", e.isp)
        -- Cached: the normalized entry is in the shared dict.
        assert.truthy(_G.ngx.shared.vn_config:get("ipq:8.8.8.8"))
    end)

    it("serves a repeat lookup from cache without hitting the network", function()
        ipq.lookup("8.8.8.8")
        assert.are.equal(1, #http_calls)
        local e = ipq.lookup("8.8.8.8")
        assert.are.equal(1, #http_calls)  -- no second fetch
        assert.is_true(e.cached)
        assert.are.equal("Test ISP", e.isp)
    end)

    it("negative-caches failures for the negative TTL window", function()
        canned_response = "throw"
        local e, err = ipq.lookup("8.8.8.8")
        assert.is_nil(e)
        assert.truthy(err:find("network down", 1, true))
        assert.are.equal(1, #http_calls)
        -- Second attempt must NOT hit the network: served from ipq:err:.
        local e2, err2 = ipq.lookup("8.8.8.8")
        assert.is_nil(e2)
        assert.truthy(err2:find("network down", 1, true))
        assert.are.equal(1, #http_calls)
    end)

    it("answers reserved ranges locally without any HTTP call", function()
        canned_response = "throw"
        local e = ipq.lookup("192.168.1.10")
        assert.are.equal(0, #http_calls)
        assert.is_true(e.reserved)
        assert.are.equal("reserved", e.ip_type)
        -- And ::ffff:-mapped forms take the same path.
        local e2 = ipq.lookup("::ffff:10.0.0.1")
        assert.are.equal(0, #http_calls)
        assert.is_true(e2.reserved)
    end)

    it("rejects non-IP strings before touching the cache or network", function()
        local e, err = ipq.lookup("not-an-ip|injected")
        assert.is_nil(e)
        assert.are.equal(0, #http_calls)
        assert.truthy(err:find("invalid ip", 1, true))
    end)
end)
