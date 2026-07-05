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

end)
