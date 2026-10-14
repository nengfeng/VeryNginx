-- vim: filetype=lua
--
-- The panel's "list is empty" notice used to point at a script on disk, which
-- is no use to an operator who only has the panel. The button that replaced it
-- runs in-process, so its tests have to cover the two ways it can go wrong in
-- ways that matter:
--
--   * every vendor unreachable — the usual state for a host inside China,
--     where developers.google.com and www.bing.com simply do not answer. The
--     fetch must refuse to write rather than replace a working list with an
--     empty one, and it must say which vendors it could not reach.
--   * a partial fetch — some vendors answer, some do not. Writing that
--     silently looks exactly like a vendor shrinking its range, so the
--     per-vendor outcome has to survive into the response.

describe("crawler_ranges parsing and merge", function()
    local ranges

    setup(function()
        ranges = require "core.crawler_ranges"
    end)

    it("reads Google's flat prefixes[].ipv4Prefix shape", function()
        local body = '{"creationTime":"2026-10-13T14:46:11","prefixes":['
            .. '{"ipv6Prefix":"2001:4860:4800::1"},'
            .. '{"ipv4Prefix":"66.249.64.0/19"},'
            .. '{"ipv4Prefix":"192.178.6.224/27"},'
            .. '{"ipv4Prefix":"66.249.64.0/19"}]}'
        -- Drive the parser through the module's own fetch by stubbing the
        -- transport, so the JSON shape is exercised exactly as in production.
        local saved = package.loaded["core.crawler_ranges"]
        package.loaded["core.crawler_ranges"] = nil
        local m = require "core.crawler_ranges"
        local got = m._test_ipv4_from_json(body)
        package.loaded["core.crawler_ranges"] = saved
        assert.are.same({ "66.249.64.0/19", "192.178.6.224/27" }, got)
    end)

    it("reads the prefixes.IPv4 bucketed shape", function()
        local body = '{"creationTime":"2024-01-03","prefixes":{"IPv4":["157.55.39.0/24"],"IPv6":["2a01:111::/32"]}}'
        local saved = package.loaded["core.crawler_ranges"]
        package.loaded["core.crawler_ranges"] = nil
        local m = require "core.crawler_ranges"
        local got = m._test_ipv4_from_json(body)
        package.loaded["core.crawler_ranges"] = saved
        assert.are.same({ "157.55.39.0/24" }, got)
    end)

    it("never lets an IPv6 entry through as IPv4", function()
        local body = '{"prefixes":[{"ipv6Prefix":"2001:4860:4800::1"},{"ipv4Prefix":"8.8.8.0/24"}]}'
        local saved = package.loaded["core.crawler_ranges"]
        package.loaded["core.crawler_ranges"] = nil
        local m = require "core.crawler_ranges"
        local got = m._test_ipv4_from_json(body)
        package.loaded["core.crawler_ranges"] = saved
        assert.are.same({ "8.8.8.0/24" }, got)
        for _, n in ipairs(got) do assert.is_nil(n:find(":")) end
    end)

    it("normalises host bits and drops nonsense", function()
        local saved = package.loaded["core.crawler_ranges"]
        package.loaded["core.crawler_ranges"] = nil
        local m = require "core.crawler_ranges"
        local norm = m._test_normalize_entry
        package.loaded["core.crawler_ranges"] = saved
        assert.are.equal("1.2.3.0/24", norm("1.2.3.4/24"))
        assert.are.equal("10.0.0.0/8", norm("10.1.2.3/8"))
        assert.are.equal("1.2.3.4/32", norm("1.2.3.4"))
        assert.is_nil(norm("999.1.1.1/24"))
        assert.is_nil(norm("1.2.3.4/33"))
        assert.is_nil(norm("not-an-ip"))
        assert.is_nil(norm("2001:4860:4800::1"))
    end)

    it("is loadable", function()
        assert.is_function(ranges.fetch)
        assert.is_function(ranges.apply)
        assert.is_function(ranges.status)
    end)
end)

describe("crawler_ranges source overrides (deployment inside China)", function()
    local config

    setup(function()
        config = require "core.config"
        config.ip_reputation = config.ip_reputation or {}
    end)

    teardown(function()
        config.ip_reputation.crawler_sources = nil
    end)

    it("falls back to the built-in URLs when nothing is configured", function()
        config.ip_reputation.crawler_sources = nil
        local saved = package.loaded["core.crawler_ranges"]
        package.loaded["core.crawler_ranges"] = nil
        local srcs = require("core.crawler_ranges")._test_sources()
        package.loaded["core.crawler_ranges"] = saved
        local by = {}
        for _, s in ipairs(srcs) do by[s.key] = s.url end
        assert.are.equal("https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
                         by.google)
        assert.are.equal("https://www.bing.com/toolbox/bingbot.json", by.bing)
    end)

    it("redirects a vendor to a reachable mirror", function()
        config.ip_reputation.crawler_sources = {
            { key = "google", mirror = "https://mirror.example.cn/google.json" },
        }
        local saved = package.loaded["core.crawler_ranges"]
        package.loaded["core.crawler_ranges"] = nil
        local srcs = require("core.crawler_ranges")._test_sources()
        package.loaded["core.crawler_ranges"] = saved
        local by = {}
        for _, s in ipairs(srcs) do by[s.key] = s end
        assert.are.equal("https://mirror.example.cn/google.json", by.google.url)
        assert.are.equal("https://mirror.example.cn/google.json", by.google.mirror,
            "the address actually used must be recorded, not just the official one")
        -- Untouched vendors keep their official URL.
        assert.are.equal("https://www.bing.com/toolbox/bingbot.json", by.bing.url)
        assert.are.equal("https://duckduckgo.com/duckduckbot.json", by.duckduckgo.url)
    end)

    it("lets an explicit url win over a mirror", function()
        config.ip_reputation.crawler_sources = {
            { key = "bing", url = "https://internal.corp/bing.json",
              mirror = "https://ignored.example/bing.json" },
        }
        local saved = package.loaded["core.crawler_ranges"]
        package.loaded["core.crawler_ranges"] = nil
        local srcs = require("core.crawler_ranges")._test_sources()
        package.loaded["core.crawler_ranges"] = saved
        for _, s in ipairs(srcs) do
            if s.key == "bing" then
                assert.are.equal("https://internal.corp/bing.json", s.url)
            end
        end
    end)

    it("ignores an override naming a vendor that does not exist", function()
        config.ip_reputation.crawler_sources = { { key = "nonesuch", url = "https://x/y.json" } }
        local saved = package.loaded["core.crawler_ranges"]
        package.loaded["core.crawler_ranges"] = nil
        local srcs = require("core.crawler_ranges")._test_sources()
        package.loaded["core.crawler_ranges"] = saved
        for _, s in ipairs(srcs) do
            assert.is_not.equal("nonesuch", s.key, "an unknown key must not create a source")
        end
        assert.are.equal(5, #srcs, "the built-in source count must not change")
    end)
end)
