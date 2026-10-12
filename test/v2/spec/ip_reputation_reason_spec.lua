describe("ip_reputation: flag reason & signal breakdown", function()

    local rep

    setup(function()
        package.preload["bit"] = function()
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
    end)

    before_each(function()
        local s = ngx.shared.ip_reputation
        s:flush_all()
        s:delete("ip_rep:flagged_today")
    end)

    describe("get_signal_breakdown()", function()

        it("aggregates per-type events and points across slots", function()
            local ip = "10.9.0.1"
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "not_found")
            local bd = rep.get_signal_breakdown(ip)
            assert.equals(2, #bd)
            -- points desc: waf_block 2x5=10 > not_found 1x1=1
            assert.equals("waf_block", bd[1].signal)
            assert.equals(2, bd[1].events)
            assert.equals(5, bd[1].weight)
            assert.equals(10, bd[1].points)
            assert.equals("not_found", bd[2].signal)
            assert.equals(1, bd[2].events)
            assert.equals(1, bd[2].weight)
            assert.equals(1, bd[2].points)
        end)

        it("orders equal points by signal name, never pairs() order", function()
            local ip = "10.9.0.2"
            -- not_found 3x1=3 ties waf_challenge 1x3=3 → name asc breaks it
            rep.record_signal(ip, "waf_challenge")
            rep.record_signal(ip, "not_found")
            rep.record_signal(ip, "not_found")
            rep.record_signal(ip, "not_found")
            local bd = rep.get_signal_breakdown(ip)
            assert.equals(2, #bd)
            assert.equals("not_found", bd[1].signal)
            assert.equals("waf_challenge", bd[2].signal)
        end)

        it("is empty for an unknown IP", function()
            assert.equals(0, #rep.get_signal_breakdown("10.9.0.99"))
        end)

        it("never records signal types without a configured weight", function()
            local ip = "10.9.0.3"
            rep.record_signal(ip, "nonexistent_signal")
            assert.equals(0, #rep.get_signal_breakdown(ip))
        end)

    end)

    describe("flag reason snapshot", function()

        it("flag_ip captures score, threshold and breakdown at flag time", function()
            local ip = "10.9.1.1"
            rep.record_signal(ip, "waf_block")     -- 5
            rep.record_signal(ip, "waf_challenge") -- 3
            rep.flag_ip(ip, 600)
            local reason = rep.get_flag_reason(ip)
            assert.is_not_nil(reason)
            assert.equals(8, reason.score)
            assert.equals(25, reason.threshold)
            assert.equals(1000000, reason.at)
            assert.equals(2, #reason.signals)
            assert.equals("waf_block", reason.signals[1].signal)
            assert.equals(5, reason.signals[1].points)
            assert.equals("waf_challenge", reason.signals[2].signal)
            assert.equals(3, reason.signals[2].points)
        end)

        it("no reason exists before a flag is raised", function()
            local ip = "10.9.1.4"
            rep.record_signal(ip, "waf_block")
            assert.is_nil(rep.get_flag_reason(ip))
        end)

        it("list_flagged entries carry score and reason", function()
            local ip = "10.9.1.2"
            rep.record_signal(ip, "waf_block")
            rep.flag_ip(ip, 600)
            local found
            for _, e in ipairs(rep.list_flagged()) do
                if e.ip == ip then found = e end
            end
            assert.is_not_nil(found)
            assert.equals(5, found.score)
            assert.is_not_nil(found.reason)
            assert.equals(5, found.reason.score)
            assert.is_not_nil(found.expires_at)
            assert.is_not_nil(found.flagged_at)
        end)

        it("get_flag_meta returns flag timestamps while flagged", function()
            local ip = "10.9.1.5"
            rep.flag_ip(ip, 600)
            local meta = rep.get_flag_meta(ip)
            assert.is_not_nil(meta)
            assert.equals(1000000, meta.flagged_at)
            assert.equals(1000600, meta.expires_at)
        end)

        it("persists and restores the reason alongside the flag", function()
            local ip = "10.9.1.3"
            rep.record_signal(ip, "waf_block")
            rep.flag_ip(ip, 600)
            rep.persist()
            rep.clear_ip(ip)
            assert.is_nil(rep.get_flag_reason(ip))
            rep.restore()
            assert.is_true(rep.is_flagged(ip, { no_cache = true }))
            local reason = rep.get_flag_reason(ip)
            assert.is_not_nil(reason)
            assert.equals(5, reason.score)
        end)

    end)

    describe("clear_ip cleanup", function()

        it("clears score, breakdown and reason together", function()
            local ip = "10.9.2.1"
            rep.record_signal(ip, "waf_block")
            rep.flag_ip(ip, 600)
            assert.is_not_nil(rep.get_flag_reason(ip))
            assert.is_true(#rep.get_signal_breakdown(ip) > 0)
            rep.clear_ip(ip)
            assert.equals(0, rep.get_score(ip))
            assert.equals(0, #rep.get_signal_breakdown(ip))
            assert.is_nil(rep.get_flag_reason(ip))
            assert.is_false(rep.is_flagged(ip, { no_cache = true }))
        end)

    end)

    describe("score_explain()", function()

        it("exposes raw points, diversity factor and ua count", function()
            local ip = "10.9.3.1"
            rep.record_ua(ip, "UA-A")
            rep.record_ua(ip, "UA-B")
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "waf_block")
            local ex = rep.score_explain(ip)
            -- raw 15; 2 distinct UAs → df = 1 - (2-1)*0.1 = 0.9
            -- score = floor(15 * 0.9 + 0.5) = 14
            assert.equals(15, ex.raw)
            assert.equals(2, ex.ua_distinct)
            assert.near(0.9, ex.diversity, 1e-9)
            assert.equals(14, ex.score)
            assert.equals(25, ex.threshold)
            assert.equals(rep.get_score(ip), ex.score)
        end)

        it("reports zeroed inputs for an unknown IP", function()
            local ex = rep.score_explain("10.9.3.99")
            assert.equals(0, ex.score)
            assert.equals(0, ex.raw)
            assert.equals(0, ex.ua_distinct)
            assert.near(1.0, ex.diversity, 1e-9)
        end)

    end)

end)
