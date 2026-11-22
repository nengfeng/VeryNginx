-- -*- coding: utf-8 -*-
-- Regression guard for the metrics index fast path.
--
-- Every metrics.observe() writes two keys (count + sum), and each index_add()
-- used to take the single global index lock, parse the whole index string,
-- sort all entries and rewrite the string. With N workers that serialised the
-- log phase of every request and produced 367 aborts/10min in production.
--
-- A worker-local "recently indexed" cache must keep that work off the steady
-- state request path while still refreshing the entry well within data_ttl.

describe("metrics index worker-local fast path", function()
    local metrics
    local lock_dict
    local fake_time

    local function make_lock_dict()
        local adds = 0
        local held = {}
        return {
            adds = function() return adds end,
            add = function(self, k, v)
                if held[k] then return false, "exists" end
                adds = adds + 1
                held[k] = v
                return true, nil
            end,
            get = function(_, k) return held[k] end,
            delete = function(_, k) held[k] = nil end,
        }
    end

    before_each(function()
        package.loaded["core.metrics"] = nil
        metrics = require "core.metrics"
        lock_dict = make_lock_dict()
        metrics._test_set_shared(lock_dict)
        fake_time = 1000
        ngx.time = function() return fake_time end
    end)

    it("writes the index on the first observation", function()
        metrics.observe("waf_request_duration", 0.01, {})
        local idx = ngx.shared.metrics:get("__metrics_index")
        assert.is_string(idx, "the index must be written on the first call")
        assert.is_true(idx:find("waf_request_duration_count", 1, true) ~= nil)
        assert.is_true(idx:find("waf_request_duration_sum", 1, true) ~= nil)
        -- Two keys => two lock acquisitions on the first call.
        assert.is_equal(2, lock_dict.adds())
    end)

    it("skips the lock and full rewrite for repeated observations", function()
        metrics.observe("waf_request_duration", 0.01, {})
        local first_idx = ngx.shared.metrics:get("__metrics_index")
        local adds_after_first = lock_dict.adds()
        local count_after_first = ngx.shared.metrics:get("waf_request_duration_count")

        -- 50 more observations well inside the 60s refresh window.
        for _ = 1, 50 do
            fake_time = fake_time + 0.5
            metrics.observe("waf_request_duration", 0.01, {})
        end
        assert.is_equal(adds_after_first, lock_dict.adds(),
            "no further lock acquisitions inside the refresh window")
        -- The index string must be byte-identical (no rewrite churn).
        assert.is_equal(first_idx, ngx.shared.metrics:get("__metrics_index"),
            "the index string must not be rewritten on the fast path")
        -- But the VALUES must still be incremented.
        assert.is_equal(count_after_first + 50,
            ngx.shared.metrics:get("waf_request_duration_count"))
    end)

    it("forces a full rewrite once the refresh window expires", function()
        metrics.observe("waf_request_duration", 0.01, {})
        local adds_after_first = lock_dict.adds()
        fake_time = fake_time + 61
        metrics.observe("waf_request_duration", 0.01, {})
        assert.is_true(lock_dict.adds() > adds_after_first,
            "the stale cache entry must trigger a full index write")
    end)

    it("does not mark a key known when the lock cannot be acquired", function()
        local held_dict = { _v = {} }
        function held_dict:add() return false, "lock held" end
        function held_dict:get(k) return self._v[k] end
        function held_dict:set(k, v) self._v[k] = v; return true, nil end
        function held_dict:incr(k, d)
            self._v[k] = (self._v[k] or 0) + d
            return self._v[k]
        end
        function held_dict:delete(k) self._v[k] = nil end
        local saved_sleep = ngx.sleep
        ngx.sleep = function() end -- swallow the retry sleep in this unit test
        metrics._test_set_shared(held_dict)
        local ok = pcall(function()
            metrics.observe("waf_request_duration", 0.01, {})
        end)
        ngx.sleep = saved_sleep
        assert.is_true(ok)

        -- Swap in a working lock dict: the next call MUST do a full write
        -- because the failed call above must not have populated the cache.
        metrics._test_set_shared(lock_dict)
        metrics.observe("waf_request_duration", 0.01, {})
        assert.is_equal(2, lock_dict.adds(),
            "a failed lock acquisition must not mark the key as known")
    end)
end)
