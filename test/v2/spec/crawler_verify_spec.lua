-- vim: filetype=lua
--
-- Baiduspider publishes no IP range file, so it is verified by DNS: the
-- reverse lookup must land inside a Baidu domain AND forward-resolving that
-- name must return the address we started from. The forward half is what
-- makes it mean anything — anyone renting a VPS can set a PTR record to
-- whatever they like, but they cannot publish an A record under baidu.com.
--
-- The tests drive a fake resolver so every outcome can be produced on demand.
-- The one that matters most is "the resolvers did not answer": that must never
-- be read as a refusal, because it turns a DNS outage into a block on real
-- search crawlers — the exact failure this design exists to avoid.

-- This rig's ngx.re has no compile/match at all (only a Lua-pattern find, which
-- has neither (?i) nor alternation), so compare.match cannot see a real
-- User-Agent here. with_pcre() installs just enough PCRE for one call and puts
-- the original back immediately, so nothing leaks into other spec files and the
-- test does not depend on setup/after_each ordering.
local function with_pcre(fn)
    local saved = ngx.re
    ngx.re = setmetatable({}, { __index = saved })
    ngx.re.compile = function(p) return p end
    ngx.re.match = function(subject, pattern)
        if type(subject) ~= "string" or type(pattern) ~= "string" then return nil end
        local body = pattern:sub(1, 4) == "(?i)" and pattern:sub(5) or pattern
        for alt in body:gmatch("[^|]+") do
            alt = alt:gsub("%b()", "")
            if subject:lower():find(alt:lower(), 1, true) then return true end
        end
        return nil
    end
    local ok, err = pcall(fn)
    ngx.re = saved
    if not ok then error(err, 0) end
end

-- Fake resolvers. nil means "this resolver does not answer".
local function install_dns(fake)
    package.loaded["resty.dns.resolver"] = nil
    package.preload["resty.dns.resolver"] = function()
        local M = { TYPE_A = 1, TYPE_PTR = 12 }
        function M.new(_, opts)
            local r = fake[opts.nameservers[1]]
            return {
                reverse_query = function(_, ip)
                    if r == nil then return nil, "resolver did not answer" end
                    return r.ptr, nil
                end,
                query = function(_, qname, o)
                    if r == nil then return nil, "resolver did not answer" end
                    return (o and o.qtype == M.TYPE_A) and r.a or r.a, nil
                end,
            }
        end
        function M.arpa_str(ip)
            local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
            return ("%d.%d.%d.%d.in-addr.arpa"):format(d, c, b, a)
        end
        return M
    end
end

local function cleanup_dns()
    package.preload["resty.dns.resolver"] = nil
    package.loaded["resty.dns.resolver"] = nil
end

local VENDOR = {
    enabled = true,
    ua_pattern = "(?i)baiduspider",
    domains = { "crawl.baidu.com", "baidu.com", "baidu.jp" },
    require_forward_confirm = true,
}

local function base_cfg(over)
    local cv = {
        enabled = true,
        resolvers = { "9.9.9.9", "8.8.4.4" },
        min_agreement = 2,
        timeout_ms = 100,
        verify_ttl_pass = 3600,
        verify_ttl_fail = 600,
        rate_limit_per_minute = 60,
        vendors = { baidu = VENDOR },
    }
    for k, v in pairs(over or {}) do cv[k] = v end
    return cv
end

describe("crawler_verify claimed_vendor", function()
    local cv, config

    setup(function()
        cv = require "core.crawler_verify"
        config = require "core.config"
    end)

    it("recognises the real User-Agent", function()
        config.ip_reputation.crawler_verify = base_cfg()
        with_pcre(function()
            local ua = "Mozilla/5.0 (compatible; Baiduspider/2.0; " ..
                       "+http://www.baidu.com/search/spider.html)"
            assert.are.equal("baidu", cv.claimed_vendor(ua))
        end)
        config.ip_reputation.crawler_verify = nil
    end)

    it("is case-insensitive, because the header is", function()
        config.ip_reputation.crawler_verify = base_cfg()
        with_pcre(function()
            assert.are.equal("baidu", cv.claimed_vendor("BAIDUSPIDER"))
            assert.are.equal("baidu",
                cv.claimed_vendor("Mozilla/5.0 (compatible; Baiduspider-image/1.0)"))
        end)
        config.ip_reputation.crawler_verify = nil
    end)

    it("does not claim ordinary browsers or unrelated crawlers", function()
        config.ip_reputation.crawler_verify = base_cfg()
        with_pcre(function()
            assert.is_nil(cv.claimed_vendor("Mozilla/5.0 (Windows NT 10.0) Chrome/126 Safari/537.36"))
            assert.is_nil(cv.claimed_vendor("Mozilla/5.0 (compatible; Googlebot/2.1)"))
            assert.is_nil(cv.claimed_vendor("Mozilla/5.0 (compatible; bingbot/2.0)"))
            assert.is_nil(cv.claimed_vendor("Mozilla/5.0 (compatible; Bytespider)"))
            assert.is_nil(cv.claimed_vendor(""))
            assert.is_nil(cv.claimed_vendor(nil))
        end)
        config.ip_reputation.crawler_verify = nil
    end)

    it("is off when configured off, and off when absent", function()
        -- Unlike ip_reputation.enable — where a missing key means "this
        -- install was already running" and failing closed would silently
        -- unflag everyone — this is a NEW feature, so the safe default for a
        -- config that predates it is off.
        config.ip_reputation.crawler_verify = { enabled = false, vendors = { baidu = VENDOR } }
        assert.is_false(cv.is_enabled())
        config.ip_reputation.crawler_verify = nil
        assert.is_false(cv.is_enabled(), "an absent block must leave the feature off")
    end)
end)

describe("crawler_verify verdicts", function()
    local cv, config, s

    -- This busted runs a describe-level setup ONCE, so relying on it to clear
    -- the shared dict between examples silently let one example's cached
    -- verdict answer the next one's question. Each example therefore resets
    -- its own state through fresh() instead.
    local function fresh(over)
        s:flush_all()
        cleanup_dns()
        config.ip_reputation.crawler_verify = base_cfg(over)
    end

    setup(function()
        cv = require "core.crawler_verify"
        config = require "core.config"
        s = ngx.shared.ip_reputation
        fresh()
    end)

    teardown(function()
        config.ip_reputation.crawler_verify = nil
        cleanup_dns()
        s:flush_all()
    end)

    local GOOD = {
        ptr = { { ptr = "baiduspider-1-2-3-4.crawl.baidu.com." } },
        a   = { { a = "1.2.3.4" } },
    }

    it("verifies when the PTR is in the vendor domain and forward-confirms", function()
        fresh()
        install_dns({ ["9.9.9.9"] = GOOD, ["8.8.4.4"] = GOOD })
        assert.are.equal(cv.VERDICT_VERIFIED, cv.verify_sync("1.2.3.4", "baidu"))
        assert.are.equal(cv.VERDICT_VERIFIED, cv.verdict("1.2.3.4"))
        assert.is_true(cv.is_verified("1.2.3.4"))
    end)

    it("accepts any configured domain, not just the first", function()
        fresh()
        install_dns({
            ["9.9.9.9"] = { ptr = { { ptr = "spider.example.baidu.jp." } }, a = { { a = "1.2.3.4" } } },
            ["8.8.4.4"] = { ptr = { { ptr = "spider.example.baidu.jp." } }, a = { { a = "1.2.3.4" } } },
        })
        assert.are.equal(cv.VERDICT_VERIFIED, cv.verify_sync("1.2.3.4", "baidu"))
    end)

    it("rejects a PTR outside the vendor domain", function()
        fresh()
        local cloudflare = {
            ptr = { { ptr = "cruz.ns.cloudflare.com." } },
            a   = { { a = "1.2.3.4" } },
        }
        install_dns({ ["9.9.9.9"] = cloudflare, ["8.8.4.4"] = cloudflare })
        assert.are.equal(cv.VERDICT_FAKE, cv.verify_sync("1.2.3.4", "baidu"))
        assert.are.equal(cv.VERDICT_FAKE, cv.verdict("1.2.3.4"))
        assert.is_false(cv.is_verified("1.2.3.4"))
    end)

    it("rejects a PTR that does not forward-confirm — what a suffix check misses", function()
        fresh()
        -- The name really is inside baidu.com, so checking only the suffix
        -- would wave this through. Only the forward lookup catches it.
        local stale = {
            ptr = { { ptr = "baiduspider-1-2-3-4.crawl.baidu.com." } },
            a   = { { a = "9.9.9.9" } },          -- points somewhere else
        }
        install_dns({ ["9.9.9.9"] = stale, ["8.8.4.4"] = stale })
        assert.are.equal(cv.VERDICT_FAKE, cv.verify_sync("1.2.3.4", "baidu"))
    end)

    it("treats an answered but empty PTR as an impersonator", function()
        fresh()
        -- DNS answered: this address simply has no reverse name. Every real
        -- vendor crawler has one.
        install_dns({ ["9.9.9.9"] = { ptr = {}, a = {} },
                      ["8.8.4.4"] = { ptr = {}, a = {} } })
        assert.are.equal(cv.VERDICT_FAKE, cv.verify_sync("1.2.3.4", "baidu"))
    end)

    it("does NOT condemn when the resolvers simply do not answer", function()
        fresh()
        -- The regression that matters most: an outage in our own DNS must not
        -- become a 403 on a real search crawler, so silence is not a verdict
        -- and must not even be cached as one.
        install_dns({ ["9.9.9.9"] = nil, ["8.8.4.4"] = nil })
        assert.are.equal(cv.VERDICT_UNKNOWN, cv.verify_sync("1.2.3.4", "baidu"))
        assert.is_nil(cv.verdict("1.2.3.4"), "unknown must not be cached as fake")
        assert.is_false(cv.is_verified("1.2.3.4"))
    end)

    it("does not condemn when only some resolvers answer", function()
        fresh()
        install_dns({ ["9.9.9.9"] = GOOD, ["8.8.4.4"] = nil })
        assert.are.equal(cv.VERDICT_UNKNOWN, cv.verify_sync("1.2.3.4", "baidu"),
            "min_agreement is 2 and only one resolver spoke")
        assert.is_nil(cv.verdict("1.2.3.4"))
    end)

    it("does not condemn on a split between resolvers", function()
        fresh()
        install_dns({
            ["9.9.9.9"] = GOOD,
            ["8.8.4.4"] = { ptr = { { ptr = "somebody-else.example.com." } }, a = {} },
        })
        assert.are.equal(cv.VERDICT_UNKNOWN, cv.verify_sync("1.2.3.4", "baidu"))
        assert.is_nil(cv.verdict("1.2.3.4"))
    end)

    it("works when only one of the configured resolvers is reachable", function()
        fresh()
        -- The inside-China shape: foreign resolvers configured but dead, one
        -- domestic resolver answering. min_agreement drops to what is left,
        -- rather than the check failing forever.
        config.ip_reputation.crawler_verify = base_cfg({ resolvers = { "9.9.9.9" } })
        install_dns({ ["9.9.9.9"] = GOOD })
        assert.are.equal(cv.VERDICT_VERIFIED, cv.verify_sync("1.2.3.4", "baidu"))
    end)

    it("forgets a verdict on request", function()
        fresh()
        install_dns({ ["9.9.9.9"] = GOOD, ["8.8.4.4"] = GOOD })
        cv.verify_sync("1.2.3.4", "baidu")
        assert.is_true(cv.is_verified("1.2.3.4"))
        cv.forget("1.2.3.4")
        assert.is_nil(cv.verdict("1.2.3.4"))
    end)

    it("does nothing for an unconfigured vendor", function()
        fresh()
        install_dns({ ["9.9.9.9"] = GOOD, ["8.8.4.4"] = GOOD })
        assert.are.equal(cv.VERDICT_UNKNOWN, cv.verify_sync("1.2.3.4", "not_a_vendor"))
    end)

    it("does not re-query an address that already has a verdict", function()
        fresh()
        local queries = 0
        package.loaded["resty.dns.resolver"] = nil
        package.preload["resty.dns.resolver"] = function()
            local M = { TYPE_A = 1, TYPE_PTR = 12 }
            function M.new()
                return {
                    reverse_query = function()
                        queries = queries + 1
                        return { { ptr = "cruz.ns.cloudflare.com." } }, nil
                    end,
                    query = function() return { { a = "1.2.3.4" } }, nil end,
                }
            end
            function M.arpa_str() return "x.arpa" end
            return M
        end
        s:set("crawler_verify:5.5.5.5", cv.VERDICT_FAKE, 60)
        cv.schedule("5.5.5.5", "baidu")
        assert.are.equal(0, queries, "an already-known address must not hit DNS again")
    end)
end)

describe("ip_reputation exemption consults all three sources", function()
    local rep, config

    setup(function()
        package.preload["bit"] = package.preload["bit"] or function()
            local m = {}
            function m.band(a, b)
                local r, v = 0, 1
                while a > 0 or b > 0 do
                    if a % 2 == 1 and b % 2 == 1 then r = r + v end
                    a, b = math.floor(a / 2), math.floor(b / 2)
                    v = v * 2
                end
                return r
            end
            return m
        end
        rep = require "core.ip_reputation"
        config = require "core.config"
        ngx.shared.ip_reputation:flush_all()
        config.ip_reputation.rule_signal_weights = { bot = 1 }
        config.ip_reputation.crawler_ip_whitelist = { "66.249.64.0/19" }
        config.ip_reputation.crawler_ip_verified = { "116.179.32.177" }
        config.ip_reputation.crawler_verify = { enabled = true, vendors = {} }
    end)

    teardown(function()
        config.ip_reputation.rule_signal_weights = nil
        config.ip_reputation.crawler_ip_whitelist = nil
        config.ip_reputation.crawler_ip_verified = nil
        config.ip_reputation.crawler_verify = nil
        ngx.shared.ip_reputation:flush_all()
    end)

    it("honours a vendor-published range", function()
        assert.is_true(rep.is_crawler_exempt({ category = "bot" }, "66.249.70.5"))
        assert.is_false(rep.is_crawler_exempt({ category = "bot" }, "66.249.128.5"))
    end)

    it("honours a DNS-verified individual address", function()
        assert.is_true(rep.is_crawler_exempt({ category = "bot" }, "116.179.32.177"),
            "crawler_ip_verified is what tools/verify_crawlers.py writes")
        assert.is_false(rep.is_crawler_exempt({ category = "bot" }, "116.179.32.178"),
            "one address in the verified list must not imply its neighbour")
    end)

    it("honours a live verdict cached by the online path", function()
        ngx.shared.ip_reputation:set("crawler_verify:203.0.113.9", "verified", 60)
        assert.is_true(rep.is_crawler_exempt({ category = "bot" }, "203.0.113.9"))
        ngx.shared.ip_reputation:set("crawler_verify:203.0.113.10", "fake", 60)
        assert.is_false(rep.is_crawler_exempt({ category = "bot" }, "203.0.113.10"),
            "a fake verdict must not exempt anything")
    end)

    it("never exempts an attack category from any source", function()
        ngx.shared.ip_reputation:set("crawler_verify:66.249.70.5", "verified", 60)
        for _, cat in ipairs({ "sqli", "xss", "rce", "ssrf" }) do
            assert.is_false(rep.is_crawler_exempt({ category = cat }, "66.249.70.5"), cat)
            assert.is_false(rep.is_crawler_exempt({ category = cat }, "116.179.32.177"), cat)
        end
    end)
end)
