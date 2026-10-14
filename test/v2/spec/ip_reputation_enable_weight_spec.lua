-- vim: filetype=lua
--
-- Three behaviours added after the reputation panel showed "今日标记 14" over a
-- five-row table and the follow-up audit found two separate problems:
--
--   1. `ip_reputation.enable` was never read by anything. Production shipped
--      `enable: false` while IPs were still being scored and flagged, so an
--      operator who believed scoring was off had no way to tell.
--   2. Every block rule cost the same 5 points, including vn_bot_0017 — a
--      UserAgent match on ccbot / claudebot / dataforseo, i.e. the ordinary AI
--      and search crawlers. Five crawler requests inside the window flagged a
--      search engine and held it at a flat 403 for the whole flag duration.
--
-- These tests pin the intended semantics rather than the code shape: an absent
-- key means enabled (a config predating the switch describes an install that
-- was running), an explicit false disables recording AND enforcement, and the
-- crawler exemption never reaches an attack rule.

describe("ip_reputation enable switch", function()

    local rep, config, s

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
        rep = require("core.ip_reputation")
        config = require "core.config"
        s = ngx.shared.ip_reputation
    end)

    local function cfg()
        return config.ip_reputation
    end

    after_each(function()
        cfg().enable = nil
        cfg().rule_signal_weights = nil
        cfg().crawler_ip_whitelist = nil
        if s then s:flush_all() end
    end)

    it("treats an ABSENT key as enabled", function()
        cfg().enable = nil
        assert.is_true(rep.is_enabled())
    end)

    it("treats an explicit false as disabled and true as enabled", function()
        cfg().enable = false
        assert.is_false(rep.is_enabled())
        cfg().enable = true
        assert.is_true(rep.is_enabled())
    end)

    it("records no signals when disabled", function()
        cfg().enable = false
        local before = rep.get_score("198.51.100.1")
        rep.record_signal("198.51.100.1", "waf_block", { id = "vn_xss_0004", category = "xss" })
        assert.are.equal(0, rep.get_score("198.51.100.1"))
        assert.are.equal(0, rep.get_score("198.51.100.1") - before)
    end)

    it("records signals when enabled", function()
        cfg().enable = true
        rep.record_signal("198.51.100.2", "waf_block", { id = "vn_xss_0004", category = "xss" })
        assert.is_true(rep.get_score("198.51.100.2") > 0)
    end)

    it("does not flag, and reports nothing flagged, when disabled", function()
        cfg().enable = false
        rep.record_signal("198.51.100.3", "waf_block")
        rep.flag_ip("198.51.100.3")
        assert.is_false(rep.is_flagged("198.51.100.3", { no_cache = true }))
    end)

    it("an already-set flag stops being enforced once disabled", function()
        cfg().enable = true
        rep.flag_ip("198.51.100.4")
        assert.is_true(rep.is_flagged("198.51.100.4", { no_cache = true }))
        -- Flipping the switch off must stop the 403 that 【前置-3】 issues,
        -- not merely stop new flags from being created.
        cfg().enable = false
        assert.is_false(rep.is_flagged("198.51.100.4", { no_cache = true }))
        -- ...and switching back on inside flag_duration restores it.
        cfg().enable = true
        assert.is_true(rep.is_flagged("198.51.100.4", { no_cache = true }))
    end)

    it("reports its state through get_stats so the panel cannot mislead", function()
        cfg().enable = false
        assert.are.equal(false, rep.get_stats().enabled)
        cfg().enable = true
        assert.are.equal(true, rep.get_stats().enabled)
    end)

    it("exposes the crawler list size so an empty list is visible", function()
        cfg().crawler_ip_whitelist = {}
        assert.are.equal(0, rep.get_stats().crawler_ip_count)
        cfg().crawler_ip_whitelist = { "66.249.64.0/19", "40.77.167.0/24" }
        assert.are.equal(2, rep.get_stats().crawler_ip_count)
    end)
end)

describe("ip_reputation per-category signal weight", function()

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
        rep = require("core.ip_reputation")
        config = require "core.config"
        ngx.shared.ip_reputation:flush_all()
    end)

    after_each(function()
        config.ip_reputation.rule_signal_weights = nil
        config.ip_reputation.crawler_ip_whitelist = nil
        config.ip_reputation.signals = nil
        ngx.shared.ip_reputation:flush_all()
    end)

    it("keeps the flat waf_block weight for categories not in the map", function()
        config.ip_reputation.rule_signal_weights = { bot = 1 }
        local w = rep.signal_weight_for_rule({ id = "vn_xss_0004", category = "xss" })
        assert.are.equal(5, w, "xss must stay at the full block weight")
    end)

    it("uses the mapped weight for the soft category", function()
        config.ip_reputation.rule_signal_weights = { bot = 1 }
        assert.are.equal(1, rep.signal_weight_for_rule({ id = "vn_bot_0017", category = "bot" }))
    end)

    it("falls back to the flat weight for a rule with no category", function()
        config.ip_reputation.rule_signal_weights = { bot = 1 }
        assert.are.equal(5, rep.signal_weight_for_rule({ id = "legacy_rule" }))
        assert.are.equal(5, rep.signal_weight_for_rule(nil))
    end)

    it("actually charges the mapped weight, not just reports it", function()
        config.ip_reputation.signals = { waf_block = 5, waf_challenge = 3,
                                         not_found = 1, challenge_fail = 5 }
        config.ip_reputation.rule_signal_weights = { bot = 1 }
        rep.record_signal("198.51.100.10", "waf_block", { id = "vn_bot_0017", category = "bot" })
        assert.are.equal(1, rep.get_score("198.51.100.10"))
        rep.record_signal("198.51.100.11", "waf_block", { id = "vn_xss_0004", category = "xss" })
        assert.are.equal(5, rep.get_score("198.51.100.11"))
    end)

    it("ignores a nonsense weight instead of trusting it", function()
        config.ip_reputation.rule_signal_weights = { bot = "one", weird = 0, neg = -3 }
        assert.are.equal(5, rep.signal_weight_for_rule({ category = "bot" }))
        assert.are.equal(5, rep.signal_weight_for_rule({ category = "weird" }))
        assert.are.equal(5, rep.signal_weight_for_rule({ category = "neg" }))
    end)

    it("the bot weight means a crawler needs 25 requests, not 5, to be flagged", function()
        config.ip_reputation.signals = { waf_block = 5, waf_challenge = 3,
                                         not_found = 1, challenge_fail = 5 }
        config.ip_reputation.rule_signal_weights = { bot = 1 }
        local crawler, attacker = "198.51.100.12", "198.51.100.13"
        -- Mirror the real request path: the filter plugin counts the request,
        -- records the signal, and is_flagged() is what promotes score to a
        -- flag (lazily, and only once min_requests is satisfied).
        local function hit(ip, n)
            for _ = 1, n do
                rep.increment_req(ip)
                rep.record_signal(ip, "waf_block", { category = "bot" })
            end
        end
        hit(crawler, 24)
        assert.is_false(rep.is_flagged(crawler, { no_cache = true }),
            "24 crawler hits must not flag the IP")
        hit(crawler, 1)
        assert.is_true(rep.is_flagged(crawler, { no_cache = true }),
            "the 25th crosses threshold 25")

        -- The contrast that matters: the same 24 requests under an attack
        -- category would have flagged at the 5th.
        ngx.shared.ip_reputation:flush_all()
        for _ = 1, 5 do
            rep.increment_req(attacker)
            rep.record_signal(attacker, "waf_block", { category = "sqli" })
        end
        assert.is_true(rep.is_flagged(attacker, { no_cache = true }),
            "an injection attempt still flags at 5 hits")
    end)
end)

describe("ip_reputation verified-crawler exemption", function()

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
        rep = require("core.ip_reputation")
        config = require "core.config"
        ngx.shared.ip_reputation:flush_all()
        config.ip_reputation.rule_signal_weights = { bot = 1 }
        config.ip_reputation.crawler_ip_whitelist = {
            "66.249.64.0/19",   -- Googlebot
            "40.77.167.0/24",   -- Bingbot
            "203.0.113.7",      -- a single bare address
        }
    end)

    after_each(function()
        config.ip_reputation.rule_signal_weights = nil
        config.ip_reputation.crawler_ip_whitelist = nil
        ngx.shared.ip_reputation:flush_all()
    end)

    it("exempts an in-range IP from a soft-category rule", function()
        assert.is_true(rep.is_crawler_exempt({ category = "bot" }, "66.249.70.5"))
        assert.is_true(rep.is_crawler_exempt({ category = "bot" }, "40.77.167.200"))
        assert.is_true(rep.is_crawler_exempt({ category = "bot" }, "203.0.113.7"))
    end)

    it("does not exempt an IP outside every range", function()
        assert.is_false(rep.is_crawler_exempt({ category = "bot" }, "66.249.128.5"))
        assert.is_false(rep.is_crawler_exempt({ category = "bot" }, "203.0.113.8"))
        assert.is_false(rep.is_crawler_exempt({ category = "bot" }, "45.32.100.1"))
    end)

    it("never exempts an attack-category rule, whatever the source", function()
        -- A crawler fetching a URL whose query carries an injection is still
        -- an injection. "It is Googlebot" is not a defence against that.
        for _, cat in ipairs({ "sqli", "xss", "rce", "lfi", "ssrf", "lfi", "bot_attack" }) do
            assert.is_false(rep.is_crawler_exempt({ category = cat }, "66.249.70.5"),
                "category " .. cat .. " must not be exempt")
        end
    end)

    it("exempts nothing while the crawler list is empty (the shipped default)", function()
        config.ip_reputation.crawler_ip_whitelist = {}
        assert.is_false(rep.is_crawler_exempt({ category = "bot" }, "66.249.70.5"))
    end)

    it("exempts nothing when the list is missing or malformed", function()
        config.ip_reputation.crawler_ip_whitelist = nil
        assert.is_false(rep.is_crawler_exempt({ category = "bot" }, "66.249.70.5"))
        config.ip_reputation.crawler_ip_whitelist = { "not-an-ip", "1.2.3.4/99", 42 }
        assert.is_false(rep.is_crawler_exempt({ category = "bot" }, "66.249.70.5"))
    end)

    it("is a no-op for rules with no category or nil", function()
        assert.is_false(rep.is_crawler_exempt({}, "66.249.70.5"))
        assert.is_false(rep.is_crawler_exempt(nil, "66.249.70.5"))
    end)

    it("does not exempt an IPv6 or malformed remote address", function()
        assert.is_false(rep.is_crawler_exempt({ category = "bot" }, "2a00:1450:4001::200e"))
        assert.is_false(rep.is_crawler_exempt({ category = "bot" }, "not-an-ip"))
    end)
end)
