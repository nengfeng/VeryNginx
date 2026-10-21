-- -*- coding: utf-8 -*-
-- ngx.sleep is not permitted in every phase.
--
-- log_by_lua* rejects it with "API disabled in the context of log_by_lua*",
-- and a throw there aborts the whole log phase: on_log.lua never reached
-- plugin.execute_log(ctx), so the request's log hooks were skipped, and the
-- metric's index entry was lost. The error log carried 367 such aborts per
-- ten minutes, 1.98 GB of log per day.
--
-- The path is not rare: the metrics index lock is a single global key, so it
-- is contended exactly when the site is busy — which is when the log phase
-- runs most.
--
-- These tests make ngx.sleep throw the way the log phase makes it throw, and
-- assert that the caller survives it instead of taking the phase down with it.

describe("a contended index lock must not abort the phase it runs in", function()

    local saved_sleep, saved_log
    local LOGS

    setup(function()
        if not _G.ngx then _G.ngx = {} end
        _G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
        _G.ngx.now = _G.ngx.now or function() return os.time() end
        _G.ngx.time = _G.ngx.time or function() return os.time() end
        _G.ngx.shared = _G.ngx.shared or setmetatable({}, {
            __index = function()
                -- A working dict for the metric storage; the LOCK dict is
                -- injected separately so it can be made to stay contended.
                local st = {}
                return {
                    get = function(_, k) return st[k] end,
                    set = function(_, k, v) st[k] = v; return true, nil end,
                    add = function(_, k, v)
                        if st[k] then return false, "exists" end
                        st[k] = v; return true, nil
                    end,
                    incr = function(_, k, d)
                        if st[k] == nil then st[k] = 0 end
                        st[k] = st[k] + d; return st[k], nil
                    end,
                    delete = function(_, k) st[k] = nil end,
                    get_keys = function() return {} end,
                }
            end,
        })
    end)

    before_each(function()
        LOGS = {}
        saved_log = ngx.log
        ngx.log = function(...)
            local parts = {}
            for i = 1, select("#", ...) do parts[#parts + 1] = tostring((select(i, ...))) end
            LOGS[#LOGS + 1] = table.concat(parts, "")
        end
    end)

    teardown(function()
        ngx.log = saved_log
        ngx.sleep = saved_sleep
    end)

    -- The real behaviour in log_by_lua*: the call is refused outright.
    local function sleep_refused()
        return error("API disabled in the context of log_by_lua*")
    end

    it("metrics.observe survives a sleep the phase refuses", function()
        saved_sleep = ngx.sleep
        ngx.sleep = sleep_refused

        package.loaded["core.metrics"] = nil
        local metrics = require "core.metrics"

        -- A dict whose add() always fails, so index_add takes the retry path
        -- and reaches the sleep.
        local shared = { _v = {} }
        function shared:add(k, v) return false, "lock held" end
        function shared:get(k) return self._v[k] end
        function shared:set(k, v) self._v[k] = v; return true, nil end
        function shared:incr(k, d) self._v[k] = (self._v[k] or 0) + d; return self._v[k] end
        function shared:delete(k) self._v[k] = nil end
        package.loaded["core.metrics"]._test_set_shared(shared)

        local ok, err = pcall(function()
            metrics.observe("waf_request_duration", 0.01, {})
        end)
        assert.is_true(ok,
            "observe must not raise when the phase forbids sleeping: " .. tostring(err))
    end)

    it("logs a warning instead of failing silently", function()
        saved_sleep = ngx.sleep
        ngx.sleep = sleep_refused

        package.loaded["core.metrics"] = nil
        local metrics = require "core.metrics"
        local shared = { _v = {} }
        function shared:add(k, v) return false, "lock held" end
        function shared:get(k) return self._v[k] end
        function shared:set(k, v) self._v[k] = v; return true, nil end
        function shared:incr(k, d) self._v[k] = (self._v[k] or 0) + d; return self._v[k] end
        function shared:delete(k) self._v[k] = nil end
        metrics._test_set_shared(shared)

        metrics.observe("waf_request_duration", 0.01, {})
        local warned = false
        for _, l in ipairs(LOGS) do
            if l:find("index lock", 1, true) then warned = true end
        end
        assert.is_true(warned,
            "the skipped index update must be visible, not silent: " ..
            table.concat(LOGS, " | "))
    end)

    it("ip_reputation's index lock gives up instead of raising", function()
        saved_sleep = ngx.sleep
        ngx.sleep = sleep_refused
        package.loaded["core.ip_reputation"] = nil
        local rep = require "core.ip_reputation"

        local shared = { _v = {} }
        function shared:add(k, v) return false, "lock held" end
        function shared:get(k) return self._v[k] end
        function shared:set(k, v) self._v[k] = v; return true, nil end
        function shared:incr(k, d) self._v[k] = (self._v[k] or 0) + d; return self._v[k] end
        function shared:delete(k) self._v[k] = nil end
        function shared:get_keys() return {} end
        rep._test_set_shared(shared)

        local ok, err = pcall(function()
            rep.record_signal("198.51.100.77", "waf_block")
        end)
        assert.is_true(ok,
            "a refused sleep must not propagate out of the caller: " .. tostring(err))
    end)
end)