describe("ip_reputation: concurrency safety", function()

    local rep

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
        rep = require("core.ip_reputation")
    end)

    before_each(function()
        ngx.shared.ip_reputation:flush_all()
    end)

    describe("shared dict incr atomicity", function()

        it("incr from multiple coroutines produces correct total", function()
            local ip = "10.0.0.1"
            local s = ngx.shared.ip_reputation
            local slot = math.floor(ngx.time() / 60)
            local key = "ip_rep:req:" .. ip .. ":" .. slot
            s:set(key, 0, 300, 0)

            -- Simulate 8 workers each incrementing 100 times
            local co_list = {}
            for w = 1, 8 do
                co_list[w] = coroutine.create(function()
                    for _ = 1, 100 do
                        s:incr(key, 1, 0, 300)
                        coroutine.yield()
                    end
                end)
            end

            -- Round-robin schedule until all complete
            local alive = #co_list
            while alive > 0 do
                alive = 0
                for _, co in ipairs(co_list) do
                    if coroutine.status(co) ~= "dead" then
                        local ok, err = coroutine.resume(co)
                        if not ok then error(err) end
                        if coroutine.status(co) ~= "dead" then
                            alive = alive + 1
                        end
                    end
                end
            end

            local final = s:get(key)
            assert.equals(800, final)
        end)

        it("record_signal accumulates correctly under concurrent calls", function()
            local ip = "10.0.0.2"

            local co_list = {}
            for w = 1, 8 do
                co_list[w] = coroutine.create(function()
                    for _ = 1, 10 do
                        rep.record_signal(ip, "waf_challenge")
                        coroutine.yield()
                    end
                end)
            end

            local alive = #co_list
            while alive > 0 do
                alive = 0
                for _, co in ipairs(co_list) do
                    if coroutine.status(co) ~= "dead" then
                        local ok, err = coroutine.resume(co)
                        if not ok then error(err) end
                        if coroutine.status(co) ~= "dead" then
                            alive = alive + 1
                        end
                    end
                end
            end

            -- 8 * 10 * 3 (waf_challenge weight) = 240
            local score = rep.get_score(ip)
            assert.equals(240, score)
        end)

    end)

    describe("ua_seen add + incr combination", function()

        it("distinct UA count is eventually consistent", function()
            local ip = "10.0.0.3"
            local uas = {"Chrome", "Firefox", "Safari", "Edge", "curl"}

            -- Record each UA type once
            for _, ua in ipairs(uas) do
                rep.record_ua(ip, ua)
            end

            -- The distinct count should reflect at least the UAs we added
            local score = rep.get_score(ip)
            -- Score should be 0 since we only recorded UAs but no signals
            assert.equals(0, score)
        end)

        it("repeated UA recording does not inflate count", function()
            local ip = "10.0.0.4"

            for _ = 1, 100 do
                rep.record_ua(ip, "Same-UA")
            end

            -- diversity factor should still be 1.0 for a single UA
            local s = ngx.shared.ip_reputation
            local slot = math.floor(ngx.time() / 60)
            s:set("ip_rep:req:" .. ip .. ":" .. slot, 10, 300)
            rep.record_signal(ip, "waf_block")
            -- score = floor(5 * 1.0 + 0.5) = 5
            assert.equals(5, rep.get_score(ip))
        end)

    end)

    describe("score cache invalidation", function()

        it("cache is invalidated after record_signal", function()
            local ip = "10.0.0.5"
            local s = ngx.shared.ip_reputation
            local slot = math.floor(ngx.time() / 60)
            s:set("ip_rep:req:" .. ip .. ":" .. slot, 10, 300)

            -- First call populates cache
            local score1 = rep.get_score(ip)
            assert.equals(0, score1)

            -- Record a signal
            rep.record_signal(ip, "waf_block")

            -- Cache should be invalidated, new score should reflect the signal
            local score2 = rep.get_score(ip)
            assert.equals(5, score2)
        end)

        it("cache hit returns stale but fast result within TTL", function()
            local ip = "10.0.0.6"
            local s = ngx.shared.ip_reputation
            local slot = math.floor(ngx.time() / 60)
            s:set("ip_rep:req:" .. ip .. ":" .. slot, 10, 300)
            s:set("ip_rep:waf:" .. ip .. ":" .. slot, 10, 300)

            -- Populates cache
            local score1 = rep.get_score(ip)
            assert.equals(10, score1)

            -- Within TTL, score should be same even if underlying data changes
            s:set("ip_rep:waf:" .. ip .. ":" .. slot, 999, 300)
            local score2 = rep.get_score(ip)
            assert.equals(10, score2)
        end)

    end)

    describe("is_flagged cache invalidation", function()

        it("cache returns correct result after state change", function()
            local ip = "10.0.0.7"
            local s = ngx.shared.ip_reputation
            local slot = math.floor(ngx.time() / 60)
            s:set("ip_rep:req:" .. ip .. ":" .. slot, 10, 300)

            -- Not flagged initially
            assert.is_false(rep.is_flagged(ip))

            -- Trigger auto-flag
            for _ = 1, 6 do
                rep.record_signal(ip, "waf_block")
            end

            -- no_cache=true should see the change immediately
            assert.is_true(rep.is_flagged(ip, { no_cache = true }))
        end)

    end)

    describe("whitelist cache", function()

        it("whitelist lookup is cached and returns consistent result", function()
            -- First lookup caches the result
            assert.is_false(rep.is_whitelisted("192.168.1.100"))

            -- Should return same result from cache
            assert.is_false(rep.is_whitelisted("192.168.1.100"))
        end)

    end)

end)
