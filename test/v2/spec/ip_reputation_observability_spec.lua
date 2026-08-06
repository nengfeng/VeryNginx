describe("ip_reputation: observability integration", function()

    local rep, metrics

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
        metrics = require("core.metrics")
    end)

    before_each(function()
        local s = ngx.shared.ip_reputation
        s:flush_all()
        s:delete("ip_rep:flagged_today")
        local ms = ngx.shared.metrics
        ms:flush_all()
    end)

    describe("get_stats() flagged_today", function()

        it("increments flagged_today when IP is auto-flagged", function()
            local ip = "10.0.0.1"
            local s = ngx.shared.ip_reputation
            local slot = math.floor(ngx.time() / 60)
            s:set("ip_rep:req:" .. ip .. ":" .. slot, 10, 300)
            local before = rep.get_stats().flagged_today or 0
            -- Trigger auto-flag: 6 x waf_block (weight 5) = 30 >= threshold 25
            for _ = 1, 6 do
                rep.record_signal(ip, "waf_block")
            end
            -- is_flagged triggers the actual flag_ip call which increments flagged_today
            assert.is_true(rep.is_flagged(ip, { no_cache = true }))
            local stats = rep.get_stats()
            assert.equals(before + 1, stats.flagged_today)
        end)

        it("flagged_today counts multiple distinct IPs", function()
            local s = ngx.shared.ip_reputation
            local slot = math.floor(ngx.time() / 60)
            local before = rep.get_stats().flagged_today or 0
            for i = 1, 3 do
                local ip = "10.0.1." .. i
                s:set("ip_rep:req:" .. ip .. ":" .. slot, 10, 300)
                for _ = 1, 6 do
                    rep.record_signal(ip, "waf_block")
                end
                -- Trigger auto-flag check
                assert.is_true(rep.is_flagged(ip, { no_cache = true }))
            end
            local stats = rep.get_stats()
            assert.equals(before + 3, stats.flagged_today)
        end)

        it("flagged count matches list_flagged length", function()
            rep.flag_ip("10.0.0.10", 600)
            rep.flag_ip("10.0.0.11", 600)
            local stats = rep.get_stats()
            local flagged = rep.list_flagged()
            assert.equals(#flagged, stats.flagged)
        end)

    end)

    describe("persist() / restore() round-trip", function()

        it("preserves flagged IPs with metadata", function()
            rep.flag_ip("10.0.0.20", 600)
            rep.flag_ip("10.0.0.21", 600)

            rep.persist()

            -- Clear all state
            rep.clear_ip("10.0.0.20")
            rep.clear_ip("10.0.0.21")
            assert.is_false(rep.is_flagged("10.0.0.20"))
            assert.is_false(rep.is_flagged("10.0.0.21"))

            -- Restore
            rep.restore()

            assert.is_true(rep.is_flagged("10.0.0.20"))
            assert.is_true(rep.is_flagged("10.0.0.21"))
        end)

        it("handles empty state gracefully", function()
            rep.persist()
            rep.restore()
            -- flagged IPs should be 0 (no IPs were flagged)
            local flagged = rep.list_flagged()
            assert.equals(0, #flagged)
        end)

    end)

    describe("record_signal weight accumulation", function()

        it("waf_challenge weight 3 accumulates correctly", function()
            local ip = "10.0.0.30"
            local s = ngx.shared.ip_reputation
            local slot = math.floor(ngx.time() / 60)
            s:set("ip_rep:req:" .. ip .. ":" .. slot, 10, 300)
            rep.record_signal(ip, "waf_challenge")
            rep.record_signal(ip, "waf_challenge")
            assert.equals(6, rep.get_score(ip))
        end)

        it("mixed signals sum correctly", function()
            local ip = "10.0.0.31"
            local s = ngx.shared.ip_reputation
            local slot = math.floor(ngx.time() / 60)
            s:set("ip_rep:req:" .. ip .. ":" .. slot, 10, 300)
            -- waf_challenge=3, waf_block=5, not_found=1, challenge_fail=5
            rep.record_signal(ip, "waf_challenge")
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "not_found")
            rep.record_signal(ip, "challenge_fail")
            assert.equals(14, rep.get_score(ip))
        end)

        it("score reflects diversity factor with multiple UAs", function()
            local ip = "10.0.0.32"
            local s = ngx.shared.ip_reputation
            local slot = math.floor(ngx.time() / 60)
            s:set("ip_rep:req:" .. ip .. ":" .. slot, 10, 300)
            rep.record_ua(ip, "Chrome")
            rep.record_ua(ip, "Firefox")
            rep.record_ua(ip, "Safari")
            -- 3 distinct UAs: df = 1.0 - (3-1)*0.1 = 0.8
            for _ = 1, 3 do
                rep.record_signal(ip, "waf_block")
            end
            -- score = floor(15 * 0.8 + 0.5) = floor(12.5) = 12
            assert.equals(12, rep.get_score(ip))
        end)

    end)

    describe("observability metrics collection", function()

        it("collects ip_reputation stats as metrics", function()
            rep.flag_ip("10.0.0.40", 600)
            rep.set_pending("10.0.0.41")

            local obs = require("core.observability")
            obs._collect_ip_reputation_stats()

            local s = ngx.shared.metrics
            local flagged = s:get("ip_reputation_flagged_total")
            local pending = s:get("ip_reputation_pending_total")
            assert.is_not_nil(flagged)
            assert.is_not_nil(pending)
        end)

        it("collects top scored IPs", function()
            local ip = "10.0.0.42"
            rep.flag_ip(ip, 600)
            local s = ngx.shared.ip_reputation
            local slot = math.floor(ngx.time() / 60)
            s:set("ip_rep:waf:" .. ip .. ":" .. slot, 30, 300)

            local obs = require("core.observability")
            obs._collect_ip_reputation_stats()

            local ms = ngx.shared.metrics
            local msl = ngx.shared.metrics_labeled
            -- Per-IP score gauges are high-cardinality series and now live in
            -- the dedicated metrics_labeled dict (core `metrics` stays clean).
            local found_score = false
            for _, k in ipairs(ms:get_keys()) do
                if k:find("ip_reputation_score") then
                    found_score = true
                    break
                end
            end
            if not found_score then
                for _, k in ipairs(msl:get_keys()) do
                    if k:find("ip_reputation_score") then
                        found_score = true
                        break
                    end
                end
            end
            assert.is_true(found_score)
        end)

    end)

end)
