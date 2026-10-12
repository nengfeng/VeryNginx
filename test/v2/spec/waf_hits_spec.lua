-- -*- coding: utf-8 -*-
-- @Disc    : WAF hit recording, ring buffer, and stats tests

describe("waf: hit recording and ring buffer", function()

    local waf

    setup(function()
        package.preload["bit"] = function()
            local m = {}
            function m.band(a, b)
                local r, v = 0, 1
                while a > 0 or b > 0 do
                    if a % 2 == 1 and b % 2 == 1 then r = r + v end
                    a, b = math.floor(a / 2), math.floor(b / 2), v * 2
                end
                return r
            end
            return m
        end
        waf = require("waf-rule-manager")
        require("matcher.init").register("URI", require("matcher.uri").test)
        -- Clear shared dict state between tests
        ngx.shared.vn_config:flush_all()
    end)

    local function make_ctx(overrides)
        overrides = overrides or {}
        return {
            request = {
                uri = overrides.uri or "/test",
                remote_addr = overrides.remote_addr or "10.0.0.1",
                user_agent = overrides.user_agent or "Mozilla/5.0",
                scheme = "http",
            },
            match_cache = {},
            match_cache_size = 0,
            set_action = function() end,
            get_data = function() return nil end,
        }
    end

    it("record_hit does not error", function()
        local ctx = make_ctx({ uri = "/test" })
        waf.record_hit("test_rule", ctx)
        assert.is_true(true)
    end)

    it("get_recent_hits returns recorded hits", function()
        local ctx = make_ctx({ uri = "/api/user", ip = "10.0.0.2" })
        waf.record_hit("test_rule", ctx, "block")
        local hits = waf.get_recent_hits(10)
        assert.is_true(#hits >= 1, "expected at least one hit in ring buffer, got " .. #hits)
    end)

    it("ring buffer respects max size", function()
        for i = 1, 110 do
            local ctx = make_ctx({ uri = "/path/" .. i })
            waf.record_hit("rule_" .. i, ctx)
        end
        local hits = waf.get_recent_hits(200)
        assert.is_true(#hits <= 100, "ring buffer should not exceed 100 entries")
    end)

    it("ring_idx is present for drill-down", function()
        local ctx = make_ctx({ uri = "/drill/test", ip = "10.0.0.99" })
        waf.record_hit("drill_rule", ctx, "block")
        local hits = waf.get_recent_hits(10)
        local found = false
        for _, h in ipairs(hits) do
            if h.uri == "/drill/test" then
                assert.is_not_nil(h.ring_idx, "ring_idx should be set for drill-down")
                found = true
                break
            end
        end
        assert.is_true(found)
    end)

    it("per-rule sampling cap stops a hot rule monopolizing the buffer", function()
        local shared = ngx.shared.vn_config
        local tail_before = tonumber(shared:get("waf_hit:tail") or 0)
        -- simulate a hot rule firing on every request (e.g. a log rule on /login)
        for i = 1, 500 do
            waf.record_hit("hot_rule", make_ctx({ uri = "/login" }))
        end
        -- another rule must still get its sample recorded
        waf.record_hit("other_rule", make_ctx({ uri = "/precious" }), "block")
        local tail_after = tonumber(shared:get("waf_hit:tail") or 0)
        local sampled = tail_after - tail_before
        assert.is_true(sampled <= 210,
            "hot rule capped: expected <=210 sampled hits, got " .. sampled)
        -- and the hot rule's per-day stats stay exact (uncapped)
        local day = os.date("!%Y%m%d")
        local today = tonumber(shared:get("waf_rule_stats:hot_rule:today:" .. day) or 0)
        assert.are.equal(500, today, "per-day counter must count every hit")
        -- other rule's hit is in the recent-hits ring
        local hits = waf.get_recent_hits(100)
        local found = false
        for _, h in ipairs(hits) do
            if h.rule_id == "other_rule" and h.uri == "/precious" then
                found = true
                break
            end
        end
        assert.is_true(found, "other rule's hit must not be evicted by the hot rule")
    end)

end)
