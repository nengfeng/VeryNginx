-- -*- coding: utf-8 -*-
-- Tests for core/ip_quality: response parsing, ip_type classification,
-- cache/negative-cache behavior, reserved-range short-circuit, key
-- fingerprint invalidation, AbuseIPDB risk enrichment and the ipinfo
-- fallback provider — all without network (resty.http is mocked with a
-- URL-routing stub that records every call).

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5
_G.ngx.time = function() return 1700000000 end
_G.ngx.now = function() return 1700000000 end
_G.ngx.md5 = function(s) return "md5_" .. tostring(s) end

_G.ngx.shared = setmetatable({_cache = {}}, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v) st[k] = v; return true, nil end,
                add = function(_, k, v) if st[k] then return false, "exists" end; st[k] = v; return true, nil end,
                delete = function(_, k) st[k] = nil end,
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
            }
        end
        return t._cache[name]
    end,
})

-- resty.http mock: URL-routing stub. http_routes is an array of
-- {match=..., status=..., body=..., throw=...}; the FIRST matching route
-- wins, non-matching URLs return 500 (which the code treats as a failure).
local http_calls = {}
local http_routes = {}
package.preload["resty.http"] = function()
    return {
        new = function()
            return {
                set_timeout = function() end,
                request_uri = function(self, url, opts)
                    http_calls[#http_calls + 1] = url
                    for _, r in ipairs(http_routes) do
                        if url:find(r.match, 1, true) then
                            if r.throw then
                                -- Mirror resty.http's failure contract: return
                                -- (nil, err), never raise. The module's
                                -- fetch/fetch_abuse/fetch_ipinfo all branch on
                                -- `if not res` and surface tostring(err), so a
                                -- thrown Lua error would escape pcall and fail
                                -- the test with the wrong message.
                                return nil, r.throw
                            end
                            return { status = r.status or 200, body = r.body or "" }
                        end
                    end
                    return { status = 500, body = "no route for " .. url }
                end,
            }
        end,
    }
end

local BASE_BODY = '{"status":"success","isp":"Test ISP","hosting":true,' ..
    '"country":"United States","countryCode":"US","regionName":"Virginia",' ..
    '"city":"Ashburn","zip":"20149","timezone":"America/New_York",' ..
    '"as":"AS15169 Google LLC","reverse":"dns.google","proxy":false,' ..
    '"mobile":false,"query":"8.8.8.8"}'
local ABUSE_BODY = '{"data":{"abuseConfidenceScore":87,"totalReports":42,' ..
    '"isTor":false,"usageType":"Data Center/Web Hosting/Transit"}}'
local IPINFO_BODY = '{"ip":"8.8.8.8","hostname":"dns.google",' ..
    '"city":"Mountain View","region":"California","country":"US",' ..
    '"org":"AS15169 Google LLC","postal":"94043","timezone":"America/Los_Angeles"}'

local function set_config(keys)
    package.loaded["core.config"] = { geoip = keys or {} }
end

-- Fresh module per test: config stub in place, caches empty, mock reset.
local function setup(keys)
    http_calls = {}
    http_routes = {}
    _G.ngx.shared.vn_config:flush_all()
    set_config(keys)
    package.loaded["core.ip_quality"] = nil
    return require "core.ip_quality"
end

after_each(function()
    -- AGENTS 9.3: clear the fakes (loaded AND preload) or this file poisons
    -- every spec that runs after it in the same busted process.
    package.loaded["core.config"] = nil
    package.loaded["core.ip_quality"] = nil
    package.loaded["resty.http"] = nil
end)

describe("ip_quality.parse_response", function()
    local ipq
    before_each(function() ipq = setup() end)

    it("parses a success response and classifies ip_type", function()
        local e = ipq.parse_response(BASE_BODY)
        assert.are.equal("Test ISP", e.isp)
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
        http_routes = { { match = "ip-api.com", status = 200, body = BASE_BODY } }
    end)

    it("fetches, caches and returns the entry on a miss", function()
        local e = ipq.lookup("8.8.8.8")
        assert.are.equal(1, #http_calls)
        assert.are.equal("Test ISP", e.isp)
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
        http_routes = { { match = "ip-api.com", throw = "network down" } }
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
        http_routes = { { match = "ip-api.com", throw = "network down" } }
        local e = ipq.lookup("192.168.1.10")
        assert.are.equal(0, #http_calls)
        assert.is_true(e.reserved)
        assert.are.equal("reserved", e.ip_type)
        -- ::ffff:-mapped forms take the same path.
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

describe("ip_quality.lookup provider chain (phase 2)", function()
    it("enriches with AbuseIPDB risk when a key is configured", function()
        local ipq = setup({ abuseipdb_key = "testkey" })
        http_routes = {
            { match = "ip-api.com", status = 200, body = BASE_BODY },
            { match = "api.abuseipdb.com", status = 200, body = ABUSE_BODY },
        }
        local e = ipq.lookup("8.8.8.8")
        assert.are.equal(2, #http_calls)
        assert.truthy(e.risk)
        assert.are.equal(87, e.risk.score)
        assert.are.equal(42, e.risk.reports)
        assert.is_false(e.risk.tor)
    end)

    it("degrades without risk when AbuseIPDB fails (lookup still succeeds)", function()
        local ipq = setup({ abuseipdb_key = "testkey" })
        http_routes = {
            { match = "ip-api.com", status = 200, body = BASE_BODY },
            { match = "api.abuseipdb.com", throw = "network down" },
        }
        local e = ipq.lookup("8.8.8.8")
        assert.is_nil(e.risk)
        assert.are.equal("Test ISP", e.isp)  -- base entry intact
    end)

    it("falls back to ipinfo when the ip-api call fails", function()
        local ipq = setup({ ipinfo_token = "testtoken" })
        http_routes = {
            { match = "ip-api.com", throw = "rate limited" },
            { match = "ipinfo.io", status = 200, body = IPINFO_BODY },
        }
        local e = ipq.lookup("8.8.8.8")
        assert.are.equal("ipinfo.io", e.source)
        assert.are.equal("unknown", e.ip_type)  -- free ipinfo has no type flags
        assert.are.equal("California", e.region)
        assert.are.equal("US", e.country_code)
    end)

    it("invalidates cached entries when the enrichment keys change", function()
        -- First lookup with no keys: entry cached with fp "".
        local ipq = setup()
        http_routes = { { match = "ip-api.com", status = 200, body = BASE_BODY } }
        ipq.lookup("8.8.8.8")
        assert.are.equal(1, #http_calls)
        -- Keys added: the cached entry (fp "") must be re-fetched, and the
        -- new round includes the AbuseIPDB call. Reset the call log so the
        -- assertion measures only the second lookup (http_calls accumulates
        -- across lookups, not per-lookup).
        set_config({ abuseipdb_key = "newkey" })
        package.loaded["core.ip_quality"] = nil
        ipq = require "core.ip_quality"
        http_routes = {
            { match = "ip-api.com", status = 200, body = BASE_BODY },
            { match = "api.abuseipdb.com", status = 200, body = ABUSE_BODY },
        }
        http_calls = {}
        local e = ipq.lookup("8.8.8.8")
        assert.are.equal(2, #http_calls)  -- re-fetched, not served from cache
        assert.truthy(e.risk)
    end)
end)
