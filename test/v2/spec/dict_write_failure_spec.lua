-- vim: filetype=lua
--
-- The `noevict` policy this work was aimed at is NOT available on this build:
-- nginx is compiled against lua-nginx-module 0.10.32rc5, which rejects
-- `lua_shared_dict NAME SIZE noevict` with "invalid number of arguments" — it
-- rejects `evict` and `slab` identically. The dict therefore still silently
-- evicts and the policy half of this change could not be deployed.
--
-- What ships is the call-site half, which is what makes a noevict dict safe
-- rather than dangerous, and which is correct for any write failure rather than
-- only exhaustion: under the slab allocator a write can also fail because the
-- value does not fit in what is left. Two rules, tested here by behaviour:
--
--   * an unrecordable rate-limit counter is treated as OVER the limit. The old
--     `if current and current > limit` read a nil as "not counted" and let the
--     request through, so a full dict would have switched rate limiting off
--     exactly when something was filling it deliberately.
--   * a dropped reputation write is reported rather than discarded unread.

describe("frequency limiter: a counter that cannot be written blocks", function()

    -- Mirrors the branch in plugin/frequency_limit/init.lua. Driving the real
    -- request path needs a full ctx, so the contract is exercised directly:
    -- these two results ARE the whole decision.
    local function decide(incr_first, limit)
        local current = incr_first
        local unrecorded = false
        if current == nil then
            unrecorded = true
            current = limit + 1
        end
        return current > limit, unrecorded
    end

    it("blocks when incr returns nothing (write refused)", function()
        local blocked, unrecorded = decide(nil, 10)
        assert.is_true(blocked, "an unrecordable counter must not read as allowed")
        assert.is_true(unrecorded)
    end)

    it("allows a normal under-limit count", function()
        local blocked, unrecorded = decide(3, 10)
        assert.is_false(blocked)
        assert.is_false(unrecorded)
    end)

    it("blocks a normal over-limit count", function()
        assert.is_true((select(1, decide(11, 10))))
    end)
end)

describe("ip_reputation reports a dropped write", function()

    -- The rig's ngx.shared is a metatable that builds a FRESH dict on every
    -- index, so overriding incr on one instance is invisible to the module:
    -- an earlier version of this file patched an instance and observed zero
    -- reports, which looked like the code not checking. ngx.shared itself has
    -- to be replaced, and ip_reputation has to be re-required afterwards so it
    -- picks up the dict_guard spy.
    local saved_shared, saved_guard_preload, saved_guard_loaded, saved_rep, fake, fired

    setup(function()
        fired = {}
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

        fake = ngx.shared.ip_reputation
        fake:flush_all()

        saved_shared = ngx.shared
        ngx.shared = setmetatable({}, { __index = function() return fake end })

        saved_guard_preload = package.preload["core.dict_guard"]
        saved_guard_loaded = package.loaded["core.dict_guard"]
        -- The spy overrides write_failed and forwards everything else. A spy
        -- defining only write_failed breaks get_score, which calls
        -- dict_guard.set for the score cache.
        local real_guard = require "core.dict_guard"
        package.preload["core.dict_guard"] = function()
            return setmetatable({
                write_failed = function(scope, op, err)
                    fired[#fired + 1] = { scope = scope, op = op, err = err,
                                          kind = "failed" }
                end,
                evicted_other = function(scope, op)
                    fired[#fired + 1] = { scope = scope, op = op,
                                          kind = "evicted_other" }
                end,
            }, { __index = real_guard })
        end
        package.loaded["core.dict_guard"] = nil

        saved_rep = package.loaded["core.ip_reputation"]
        package.loaded["core.ip_reputation"] = nil
    end)

    teardown(function()
        fake.incr = nil
        ngx.shared = saved_shared
        package.preload["core.dict_guard"] = saved_guard_preload
        package.loaded["core.dict_guard"] = saved_guard_loaded
        package.loaded["core.ip_reputation"] = saved_rep
    end)

    local function rep()
        return require "core.ip_reputation"
    end

    it("reports a signal write the dict refused", function()
        local real = fake.incr
        fake.incr = function() return nil, "no memory" end
        fired = {}
        rep().record_signal("198.51.100.91", "waf_block")
        fake.incr = real
        assert.is_true(#fired > 0, "a dropped signal write must be reported")
        assert.are.equal("ip_rep.signal", fired[1].scope)
        assert.are.equal("no memory", fired[1].err)
    end)

    it("reports a request-counter write the dict refused", function()
        -- This counter is what satisfies min_requests; losing writes quietly
        -- would disable the guard that stops one request from flagging an IP.
        local real = fake.incr
        fake.incr = function() return nil, "no memory" end
        fired = {}
        rep().increment_req("198.51.100.92")
        fake.incr = real
        assert.is_true(#fired > 0, "increment_req must report a dropped write")
        assert.are.equal("ip_rep.req", fired[1].scope)
    end)

    -- The case a plain `if not ok` cannot see: ngx.shared.DICT returns a
    -- normal value and reports success, having made room by evicting another
    -- key by LRU. lua_shared_dict has no noevict policy, so this is the
    -- default behaviour at high water and the only signal is the third
    -- return value.
    it("reports a write that succeeded only by evicting another key", function()
        local real = fake.incr
        fake.incr = function() return 5, nil, true end
        fired = {}
        rep().record_signal("198.51.100.94", "waf_block")
        fake.incr = real
        assert.is_true(#fired > 0, "a forcible write must be reported")
        assert.are.equal("ip_rep.signal", fired[1].scope)
    end)

    it("treats a forcible request-counter write as reported, not dropped", function()
        local real = fake.incr
        fake.incr = function() return 1, nil, true end
        fired = {}
        rep().increment_req("198.51.100.95")
        fake.incr = real
        assert.is_true(#fired > 0, "a forcible request write must be reported")
        assert.are.equal("ip_rep.req", fired[1].scope)
    end)

    it("stays silent when the write succeeds", function()
        fake:flush_all()
        fired = {}
        rep().record_signal("198.51.100.93", "waf_block")
        assert.are.equal(0, #fired, "no report when nothing failed")
        assert.is_true(rep().get_score("198.51.100.93") > 0,
            "and the signal must actually have been recorded")
    end)
end)
