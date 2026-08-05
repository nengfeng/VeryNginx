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

        it("keeps live keys and the allow snapshot index in sync (no divergence)", function()
            local s = ngx.shared.ip_reputation
            local json = (pcall(require, "cjson") and require("cjson")) or require("dkjson")

            -- Fill to cap (2/2), then try a third IP that must be rejected
            rep.record_challenge_pass("10.0.2.2")
            rep.record_challenge_pass("10.0.2.2")
            rep.record_challenge_pass("10.0.2.3")
            rep.record_challenge_pass("10.0.2.3")
            rep.record_challenge_pass("10.0.2.4")
            rep.record_challenge_pass("10.0.2.4")

            assert.is_true(rep.is_whitelisted("10.0.2.2"))
            assert.is_true(rep.is_whitelisted("10.0.2.3"))
            assert.is_false(rep.is_whitelisted("10.0.2.4"))

            -- The excluded IP must have neither a live key nor an index entry
            assert.is_nil(s:get("ip_rep:awl:10.0.2.4"))

            local raw = s:get("ip_rep:awl_index")
            assert.is_not_nil(raw)
            local ok, idx = pcall(json.decode, raw)
            assert.is_true(ok, "awl_index must be valid JSON")
            assert.equals(2, #idx)

            local seen = {}
            for _, eip in ipairs(idx) do
                seen[eip] = true
                -- Every index entry must have a live key (snapshot source of truth)
                assert.is_not_nil(s:get("ip_rep:awl:" .. eip), "index entry missing live key")
            end
            assert.is_true(seen["10.0.2.2"])
            assert.is_true(seen["10.0.2.3"])
            assert.is_nil(seen["10.0.2.4"], "excluded IP must not appear in the index")
        end)

    end)

    describe("restore() rebuilds JSON indices", function()

        before_each(function()
            ngx.shared.ip_reputation:flush_all()
        end)

        after_each(function()
            local cfg = require("core.config")
            local path = cfg.resolve_path() .. "/configs/ip-reputation-flagged.json"
            os.remove(path)
            local tmp = path .. ".tmp"
            os.remove(tmp)
        end)

        it("restored flagged IPs survive new flags (index rebuilt)", function()
            rep.flag_ip("10.0.3.1", 600)
            rep.flag_ip("10.0.3.2", 600)
            rep.persist()

            -- Wipe shared dict completely (simulates fresh start)
            ngx.shared.ip_reputation:flush_all()
            rep.restore()

            assert.is_true(rep.is_flagged("10.0.3.1"))
            assert.is_true(rep.is_flagged("10.0.3.2"))
            assert.equals(2, #rep.list_flagged())

            -- A new flag populates the JSON index; restored IPs must NOT vanish
            rep.flag_ip("10.0.3.3", 600)
            local ips = {}
            for _, e in ipairs(rep.list_flagged()) do ips[e.ip] = true end
            assert.is_true(ips["10.0.3.1"], "restored IP lost after index repopulated")
            assert.is_true(ips["10.0.3.2"], "restored IP lost after index repopulated")
            assert.is_true(ips["10.0.3.3"])
        end)

        it("pending_count reflects live pending entries", function()
            -- Same-IP duplicate challenges must count once
            rep.set_pending("10.0.4.1")
            rep.set_pending("10.0.4.1")
            rep.set_pending("10.0.4.2")
            assert.equals(2, rep.pending_count())
            assert.equals(2, rep.get_stats().pending)

            -- TTL expiry of the pending key frees the slot (no monotonic leak)
            ngx.shared.ip_reputation:delete("ip_rep:pending:10.0.4.1")
            assert.equals(1, rep.pending_count())

            -- Explicit clear also reduces the live count
            rep.clear_pending("10.0.4.2")
            assert.equals(0, rep.pending_count())
        end)

    end)

    describe("per-IP key and JSON index stay in sync on remove", function()

        before_each(function()
            ngx.shared.ip_reputation:flush_all()
            local cfg = require("core.config")
            cfg.ip_reputation.pending_ttl = 60
        end)

        after_each(function()
            local cfg = require("core.config")
            cfg.ip_reputation.pending_ttl = nil
        end)

        it("clear_pending removes both the per-IP key and the index entry", function()
            local s = ngx.shared.ip_reputation
            local json = (pcall(require, "cjson") and require("cjson")) or require("dkjson")
            rep.set_pending("10.0.8.1")
            assert.is_true(rep.has_pending("10.0.8.1"),
                "per-IP pending key should exist after set")
            rep.clear_pending("10.0.8.1")
            assert.is_false(rep.has_pending("10.0.8.1"))
            local raw = s:get("ip_rep:pending_index")
            local idx = {}
            if raw then
                local okd, dec = pcall(json.decode, raw)
                assert.is_true(okd)
                idx = dec or {}
            end
            assert.is_nil(idx["10.0.8.1"], "pending index must not retain the cleared IP")
        end)

        it("clear_ip removes both the per-IP flag key and the flag index entry", function()
            local s = ngx.shared.ip_reputation
            local json = (pcall(require, "cjson") and require("cjson")) or require("dkjson")
            rep.flag_ip("10.0.8.2", 600)
            assert.is_true(rep.is_flagged("10.0.8.2"))
            rep.clear_ip("10.0.8.2")
            assert.is_false(rep.is_flagged("10.0.8.2"))
            local raw = s:get("ip_rep:flagged_index")
            local idx = {}
            if raw then
                local okd, dec = pcall(json.decode, raw)
                assert.is_true(okd)
                idx = dec or {}
            end
            assert.is_nil(idx["10.0.8.2"], "flag index must not retain the cleared IP")
        end)

    end)

    describe("flagged index compaction (dead-entry pruning)", function()

        before_each(function()
            ngx.shared.ip_reputation:flush_all()
        end)

        it("drops dead entries once the index grows past the threshold", function()
            local s = ngx.shared.ip_reputation
            local json = (pcall(require, "cjson") and require("cjson")) or require("dkjson")

            -- Build an index above the compaction threshold (32)
            for i = 1, 40 do
                rep.flag_ip(string.format("10.0.6.%d", i), 600)
            end

            -- Simulate expiry of the first 10 by removing their per-IP markers;
            -- their index entries linger until the next compacting add.
            for i = 1, 10 do
                s:delete("ip_rep:flagged_idx:10.0.6." .. i)
            end

            -- Next flag triggers compaction (decoded list >= 32)
            rep.flag_ip("10.0.6.99", 600)

            local raw = s:get("ip_rep:flagged_index")
            assert.is_not_nil(raw)
            local ok, idx = pcall(json.decode, raw)
            assert.is_true(ok, "flagged_index must be valid JSON")
            assert.equals(31, #idx, "index should hold 30 live + 1 new")
            local seen = {}
            for _, eip in ipairs(idx) do seen[eip] = true end
            for i = 1, 10 do
                assert.is_nil(seen["10.0.6." .. i], "dead IP must be compacted away")
            end
            for i = 11, 40 do
                assert.is_true(seen["10.0.6." .. i], "live IP must survive compaction")
            end
            assert.is_true(seen["10.0.6.99"])
        end)

        it("compaction never drops entries while under the threshold", function()
            local s = ngx.shared.ip_reputation
            local json = (pcall(require, "cjson") and require("cjson")) or require("dkjson")

            -- Below the threshold: dead entries stay until a compacting add
            for i = 1, 10 do
                rep.flag_ip(string.format("10.0.7.%d", i), 600)
            end
            for i = 1, 5 do
                s:delete("ip_rep:flagged_idx:10.0.7." .. i)
            end

            rep.flag_ip("10.0.7.99", 600)

            local raw = s:get("ip_rep:flagged_index")
            local ok, idx = pcall(json.decode, raw)
            assert.is_true(ok)
            assert.equals(11, #idx, "below threshold: all entries kept")
        end)

    end)

    describe("score cache invalidation", function()

        before_each(function()
            ngx.shared.ip_reputation:flush_all()
        end)

        it("clear_score invalidates the score cache", function()
            local ip = "10.0.9.1"
            rep.record_signal(ip, "waf_block")
            local before = rep.get_score(ip)
            assert.is_true(before > 0, "score cache should be populated")
            rep.clear_score(ip)
            assert.equals(0, rep.get_score(ip), "get_score must not return a stale cached value")
        end)

        it("record_ua invalidates the score cache on a new distinct UA", function()
            local ip = "10.0.9.2"
            rep.record_ua(ip, "ua-1")
            rep.record_signal(ip, "waf_block")
            rep.record_signal(ip, "waf_block")
            local before = rep.get_score(ip)
            assert.equals(10, before, "single UA => diversity factor 1.0 => score 10")
            -- A second distinct UA lowers the diversity factor to 0.9
            rep.record_ua(ip, "ua-2")
            assert.equals(9, rep.get_score(ip), "stale cache would return the old score 10")
        end)

    end)

    describe("is_whitelisted auto-whitelist cache TTL", function()

        local real_time
        local fake_time = 1700000000

        before_each(function()
            ngx.shared.ip_reputation:flush_all()
            require("core.kernel_blocking.whitelist_generation").init_epoch()
            fake_time = 1700000000
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

        setup(function()
            real_time = ngx.time
            _G.ngx.time = function() return fake_time end
        end)

        teardown(function()
            _G.ngx.time = real_time
        end)

        it("returns true while the awl entry is still valid", function()
            rep.record_challenge_pass("10.0.3.1")
            rep.record_challenge_pass("10.0.3.1")
            assert.is_true(rep.is_whitelisted("10.0.3.1"))
        end)

        it("does not keep allow-listing after the awl entry expires", function()
            rep.record_challenge_pass("10.0.3.2")
            rep.record_challenge_pass("10.0.3.2")
            assert.is_true(rep.is_whitelisted("10.0.3.2"))
            -- Simulate the positive cache TTL (capped at the remaining awl TTL)
            -- elapsing: the stub never expires dict keys, so invalidate the
            -- generation-qualified cache by bumping the sequence.
            require("core.kernel_blocking.whitelist_generation").bump_sequence()
            -- Advance the clock past the full awl.ttl (60s). The live awl key
            -- is still present in the stub; remaining TTL must be computed from
            -- the stored creation time, not cached for a second full awl.ttl.
            fake_time = fake_time + 120
            assert.is_false(rep.is_whitelisted("10.0.3.2"))
        end)

    end)

    describe("flag_ip flagged_today counting", function()

        before_each(function()
            ngx.shared.ip_reputation:flush_all()
        end)

        it("counts a re-flag of the same IP only once", function()
            rep.flag_ip("10.0.5.1", 600)
            rep.flag_ip("10.0.5.1", 600)
            local s = ngx.shared.ip_reputation
            assert.equals(1, s:get("ip_rep:flagged_today"))
        end)

        it("still counts each distinct IP", function()
            rep.flag_ip("10.0.5.2", 600)
            rep.flag_ip("10.0.5.3", 600)
            local s = ngx.shared.ip_reputation
            assert.equals(2, s:get("ip_rep:flagged_today"))
        end)

        it("counts a fresh flag whose previous entry is a dead index item", function()
            local s = ngx.shared.ip_reputation
            rep.flag_ip("10.0.5.4", 600)
            assert.equals(1, s:get("ip_rep:flagged_today"))
            -- Simulate expiry: the per-IP liveness key is gone, but the dead
            -- entry lingers in the (sub-threshold, no-compact) JSON index.
            s:delete("ip_rep:flagged:10.0.5.4")
            s:delete("ip_rep:flagged_idx:10.0.5.4")
            rep.flag_ip("10.0.5.4", 600)
            assert.equals(2, s:get("ip_rep:flagged_today"),
                "a fresh flag must be counted even when a dead index entry exists")
            -- No dead+live duplicate may remain in the index
            local json = (pcall(require, "cjson") and require("cjson")) or require("dkjson")
            local raw = s:get("ip_rep:flagged_index")
            local ok, idx = pcall(json.decode, raw)
            assert.is_true(ok)
            local count = 0
            for _, v in ipairs(idx) do
                if v == "10.0.5.4" then count = count + 1 end
            end
            assert.equals(1, count, "index must hold a single entry for the IP")
        end)

    end)

    describe("_collect_pending expiry refresh", function()

        local real_time
        local fake_time = 1700000000

        before_each(function()
            ngx.shared.ip_reputation:flush_all()
            fake_time = 1700000000
            local cfg = require("core.config")
            cfg.ip_reputation.pending_ttl = 60
        end)

        after_each(function()
            local cfg = require("core.config")
            cfg.ip_reputation.pending_ttl = nil
        end)

        setup(function()
            real_time = ngx.time
            _G.ngx.time = function() return fake_time end
        end)

        teardown(function()
            _G.ngx.time = real_time
        end)

        it("drops entries that expired since the last version bump", function()
            rep.set_pending("10.0.4.1")
            assert.equals(1, #rep._collect_pending())
            -- No add/remove => pi_version unchanged (cache-hit path). The pending
            -- key would have auto-expired in the dict; stub never expires keys,
            -- so delete it explicitly and advance the wall clock past pending_ttl.
            fake_time = fake_time + 120
            ngx.shared.ip_reputation:delete("ip_rep:pending:10.0.4.1")
            assert.equals(0, #rep._collect_pending())
        end)

    end)

end)
