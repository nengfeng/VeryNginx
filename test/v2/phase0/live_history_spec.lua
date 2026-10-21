-- -*- coding: utf-8 -*-
-- History, baselines, and the failure definition.
--
-- The live minute data lives for 15 minutes, which is enough for a sparkline
-- but not for a baseline. A number without a baseline is not an alarm: "74%"
-- means nothing until you know what this host normally does.
--
-- The history is one key per host holding a text series, not one key per host
-- per minute. That keeps the statistics dict's namespace count where it was
-- (it already answers /dicts with 678 KB) and it avoids needing a NEW shared
-- dict — shared-memory zones are created by the master, so a new one needs a
-- full restart, which on a live box means clearing the rate-limit counters,
-- the reputation data and the statistics all at once.

local function make_shared()
    local st = {}
    return {
        _v = st,
        get = function(_, k) return st[k] end,
        set = function(_, k, v) st[k] = v; return true, nil end,
        add = function(_, k, v)
            if st[k] then return false, "exists" end
            st[k] = v; return true, nil
        end,
        incr = function(_, k, d, init, ttl)
            if st[k] == nil then st[k] = init or 0 end
            st[k] = st[k] + (d or 1)
            return st[k], nil
        end,
        delete = function(_, k) st[k] = nil end,
        get_keys = function() return {} end,
    }
end

describe("traffic history and baselines", function()

    local shared, live
    -- A controllable clock: ngx.now must stay a FUNCTION (core/random calls
    -- ngx.now()), so the test advances a variable rather than replacing it.
    local CLOCK = 1700000000

    setup(function()
        if not _G.ngx then _G.ngx = {} end
        _G.ngx.log = _G.ngx.log or function() end
        _G.ngx.now = function() return CLOCK end
        _G.ngx.time = function() return CLOCK end
        _G.ngx.crc32_long = _G.ngx.crc32_long or function(s)
            local h = 5381
            for i = 1, #s do h = (h * 33 + s:byte(i)) % 4294967296 end
            return h
        end
        _G.ngx.var = { http_cookie = nil, http_referer = nil }
        shared = make_shared()
        _G.ngx.shared = setmetatable({}, {
            __index = function(t, n)
                rawset(t, n, shared)
                return shared
            end,
        })
        package.loaded["core.live_stats"] = nil
        package.loaded["core.statistics"] = nil
        live = require "core.live_stats"
    end)

    teardown(function()
        package.loaded["core.live_stats"] = nil
        package.loaded["core.statistics"] = nil
    end)

    -- setup() runs once per describe, so the shared dict has to be reset per
    -- test or the counts come out too high.
    before_each(function()
        for k in pairs(shared._v) do shared._v[k] = nil end
        _G.ngx.var.http_cookie = nil
        _G.ngx.var.http_referer = nil
    end)

    local function ctx(ip, ua, uri)
        return {
            request = { host = "h.example.com", remote_addr = ip or "1.2.3.4",
                        user_agent = ua or "UA", uri = uri or "/a.php" },
            get_uri_args = function() return {} end,
        }
    end

    it("folds a minute into the history and reads it back", function()
        for _ = 1, 4 do live.record(ctx("10.0.0.1", "UA", "/a.php")) end
        for i = 1, 3 do live.record(ctx("10.0.0." .. i, "UA", "/a.php")) end
        live.roll_history()

        local hist = live.history("h.example.com", 180)
        assert.are.equal(1, #hist, "one minute was folded")
        assert.are.equal(7, hist[1].requests)
        assert.are.equal(3, hist[1].distinct_ips, "three distinct clients")
    end)

    it("keeps one key per host rather than one per minute", function()
        -- The namespace count is what made /dicts answer with 678 KB.
        for _ = 1, 3 do live.record(ctx("10.0.0.1", "UA", "/a.php")) end
        live.roll_history()
        local n = 0
        for k in pairs(shared._v) do
            if k:match("^hist:") or k:match("^histH:") then n = n + 1 end
        end
        assert.is_true(n <= 2, "at most two history keys per host, got " .. n)
    end)

    it("accumulates a baseline over the history", function()
        -- A few minutes of a steady 10 requests a minute.
        for _ = 1, 3 do
            for i = 1, 10 do live.record(ctx("10.0.0." .. i, "UA", "/a.php")) end
            live.roll_history()
            -- move to the next minute
            CLOCK = CLOCK + 60
        end
        local b = live.baseline("h.example.com")
        assert.is_true(b.minutes_covered >= 1,
            "the baseline must be built from the history")
        assert.is_truthy(b.requests_median, "and must have a median")
    end)

    it("treats only 5xx, 499 and the timeouts as backend failures", function()
        -- 403 is the WAF blocking and 429 is the rate limiter working. Counting
        -- them as failures makes the panel cry wolf exactly when the defence
        -- is doing its job — which on this deployment is all the time.
        assert.is_true(live.is_backend_failure(500))
        assert.is_true(live.is_backend_failure(502))
        assert.is_true(live.is_backend_failure(503))
        assert.is_true(live.is_backend_failure(499))
        assert.is_true(live.is_backend_failure(504))
        assert.is_false(live.is_backend_failure(403), "403 is the WAF blocking")
        assert.is_false(live.is_backend_failure(404), "404 is the backend answering")
        assert.is_false(live.is_backend_failure(429), "429 is the rate limiter")
        assert.is_false(live.is_backend_failure(200))
    end)

    it("flags a distributed scraper by its requests-per-client ratio", function()
        -- Many clients, about one request each. The 2026-10 scraper was 1.01
        -- across 3,662 addresses; a normal forum sits near 0.2.
        for i = 1, 40 do live.record(ctx("10.0.0." .. i, "UA", "/a.php")) end
        local series = live.host_series("h.example.com", 1)
        local anomalies = live.anomalies("h.example.com", series)
        local found = false
        for _, a in ipairs(anomalies) do
            if a.kind == "diverse_scraping" then found = true end
        end
        assert.is_true(found,
            "40 clients at one request each must read as a scraper")
    end)

    it("does not flag a site whose clients repeat", function()
        for _ = 1, 40 do live.record(ctx("10.0.0.1", "UA", "/a.php")) end
        local series = live.host_series("h.example.com", 1)
        local anomalies = live.anomalies("h.example.com", series)
        for _, a in ipairs(anomalies) do
            assert.is_not.equal("diverse_scraping", a.kind,
                "one client making 40 requests is not a scraper")
        end
    end)
end)