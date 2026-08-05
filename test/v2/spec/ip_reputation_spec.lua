describe("ip_reputation", function()

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

    describe("record_signal() / get_score()", function()

        it("accumulates score from signals", function()
            local ip = "10.0.0.1"
            local before = rep.get_score(ip)
            rep.record_signal(ip, "waf_challenge")
            rep.record_signal(ip, "waf_block")
            local after = rep.get_score(ip)
            assert.equals(before + 8, after)
        end)

        it("returns 0 for unknown IP", function()
            assert.equals(0, rep.get_score("10.0.0.99"))
        end)

        it("handles signal_type with no weight gracefully", function()
            rep.record_signal("10.0.0.1", "nonexistent_signal")
        end)

    end)

    describe("record_ua()", function()

        it("tracks distinct user agents and applies diversity factor", function()
            local ip = "10.0.0.2"
            rep.record_ua(ip, "Mozilla/5.0 Chrome")
            rep.record_ua(ip, "python-requests/2.28")
            rep.record_ua(ip, "curl/7.68")
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "waf_block")
            local score = rep.get_score(ip)
            assert.equals(12, score)
        end)

    end)

    describe("pending state", function()

        it("sets and detects pending status", function()
            local ip = "10.0.0.3"
            assert.is_false(rep.has_pending(ip))
            rep.set_pending(ip)
            assert.is_true(rep.has_pending(ip))
            rep.clear_pending(ip)
            assert.is_false(rep.has_pending(ip))
        end)

    end)

    describe("flag_ip() / is_flagged() / clear_ip()", function()

        it("flags an IP and detects it", function()
            local ip = "10.0.0.4"
            rep.flag_ip(ip, 600)
            assert.is_true(rep.is_flagged(ip))
        end)

        it("clear_ip removes the flag", function()
            local ip = "10.0.0.5"
            rep.flag_ip(ip, 600)
            assert.is_true(rep.is_flagged(ip))
            rep.clear_ip(ip)
            assert.is_false(rep.is_flagged(ip))
        end)

        it("is_flagged auto-flags when score exceeds threshold", function()
            local ip = "10.0.0.6"
            local s = ngx.shared.ip_reputation
            local slot = math.floor(ngx.time() / 60)
            s:set("ip_rep:req:" .. ip .. ":" .. slot, 10, 300)
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "waf_block")
            assert.is_true(rep.is_flagged(ip, { no_cache = true }))
        end)

        it("respects min_requests threshold", function()
            local ip = "10.0.0.7"
            rep.record_signal(ip, "waf_block")
            assert.is_false(rep.is_flagged(ip, { no_cache = true }))
        end)

    end)

    describe("whitelist", function()

        it("is_whitelisted returns false for empty whitelist", function()
            assert.is_false(rep.is_whitelisted("192.168.1.1"))
        end)

    end)

    describe("list_flagged() / get_stats()", function()

        it("list_flagged returns flagged IPs", function()
            rep.flag_ip("10.0.0.8", 600)
            local flagged = rep.list_flagged()
            local found = false
            for _, entry in ipairs(flagged) do
                if entry.ip == "10.0.0.8" then
                    found = true
                    assert.is_not_nil(entry.expires_at)
                    assert.is_not_nil(entry.flagged_at)
                    break
                end
            end
            assert.is_true(found)
        end)

        it("get_stats returns counts", function()
            local stats = rep.get_stats()
            assert.is_not_nil(stats.flagged)
            assert.is_not_nil(stats.pending)
            assert.is_not_nil(stats.flagged_today)
        end)

    end)

    describe("persist() / restore()", function()

        it("persist and restore round-trips flagged IPs", function()
            local ip = "10.0.0.9"
            rep.flag_ip(ip, 600)

            -- Verify flagged before persist
            assert.is_true(rep.is_flagged(ip))

            rep.persist()

            -- Clear everything
            rep.clear_ip(ip)
            assert.is_false(rep.is_flagged(ip))

            -- Restore
            rep.restore()

            -- Debug: check raw state
            local flagged_val = ngx.shared.ip_reputation:get("ip_rep:flagged:" .. ip)
            assert.is_not_nil(flagged_val, "expected flagged key to be set after restore, got nil")

            local result = rep.is_flagged(ip)
            assert.is_true(result)
        end)

        after_each(function()
            local cfg = require("core.config")
            local path = cfg.resolve_path() .. "/configs/ip-reputation-flagged.json"
            os.remove(path)
            local tmp = path .. ".tmp"
            os.remove(tmp)
        end)

    end)

    describe("auto_whitelist", function()

        before_each(function()
            ngx.shared.ip_reputation:flush_all()
            -- Initialize epoch so whitelist caches are generation-qualified
            -- and bump_sequence() actually invalidates them.
            require("core.kernel_blocking.whitelist_generation").init_epoch()
            local cfg = require("core.config")
            cfg.ip_reputation.auto_whitelist = {
                enabled = true,
                threshold = 2,
                ttl = 60,
                max_entries = 2,
            }
        end)

        after_each(function()
            local cfg = require("core.config")
            cfg.ip_reputation.auto_whitelist = nil
        end)

        it("whitelists an IP after threshold passes", function()
            local ip = "10.0.2.1"
            assert.is_false(rep.is_whitelisted(ip))
            rep.record_challenge_pass(ip)
            assert.is_false(rep.is_whitelisted(ip))
            rep.record_challenge_pass(ip)
            assert.is_true(rep.is_whitelisted(ip))
        end)

        it("caps simultaneous auto-whitelisted IPs at max_entries", function()
            rep.record_challenge_pass("10.0.2.2")
            rep.record_challenge_pass("10.0.2.2")  -- added (1/2)
            rep.record_challenge_pass("10.0.2.3")
            rep.record_challenge_pass("10.0.2.3")  -- added (2/2)
            rep.record_challenge_pass("10.0.2.4")
            rep.record_challenge_pass("10.0.2.4")  -- threshold reached, cap full -> not added
            assert.is_true(rep.is_whitelisted("10.0.2.2"))
            assert.is_true(rep.is_whitelisted("10.0.2.3"))
            assert.is_false(rep.is_whitelisted("10.0.2.4"))
        end)

        it("self-heals: expired entries free up capacity (no counter leak)", function()
            -- Fill to cap
            rep.record_challenge_pass("10.0.2.2")
            rep.record_challenge_pass("10.0.2.2")
            rep.record_challenge_pass("10.0.2.3")
            rep.record_challenge_pass("10.0.2.3")

            -- Simulate both entries expiring from the shared dict
            local s = ngx.shared.ip_reputation
            s:delete("ip_rep:awl:10.0.2.2")
            s:delete("ip_rep:awl:10.0.2.3")

            -- Capacity must be free again despite prior whitelist history
            rep.record_challenge_pass("10.0.2.4")
            rep.record_challenge_pass("10.0.2.4")
            assert.is_true(rep.is_whitelisted("10.0.2.4"))
        end)

    end)

end)
