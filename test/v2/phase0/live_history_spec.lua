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

-- Shared, mutable clock: core/random calls ngx.now(), which must stay a
-- function, so the tests advance this variable instead of replacing it.
-- make_shared() below needs it to record TTL expiry.
local CLOCK = 1700000000

local function make_shared()
    local st = {}
    local ex = {}
    return {
        _v = st,
        _e = ex,
        get = function(_, k) return st[k] end,
        set = function(_, k, v, ttl)
            st[k] = v
            if ttl then ex[k] = CLOCK + ttl end
            return true, nil
        end,
        add = function(_, k, v, ttl)
            if st[k] then return false, "exists" end
            st[k] = v
            if ttl then ex[k] = CLOCK + ttl end
            return true, nil
        end,
        incr = function(_, k, d, init, ttl)
            if st[k] == nil then st[k] = init or 0 end
            st[k] = st[k] + (d or 1)
            -- incr does not refresh an existing key's TTL (same as OpenResty);
            -- the initial TTL is set when the key is first created.
            if ttl and not ex[k] then ex[k] = CLOCK + ttl end
            return st[k], nil
        end,
        delete = function(_, k) st[k] = nil; ex[k] = nil end,
        get_keys = function() return {} end,
    }
end

describe("traffic history and baselines", function()

    local shared, live
    -- A controllable clock: ngx.now must stay a FUNCTION (core/random calls
    -- ngx.now()), so the test advances a variable rather than replacing it.
    CLOCK = 1700000000

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
        -- The rollup remembers which minute it folded last; a fresh module per
        -- test keeps that guard from leaking across cases.
        package.loaded["core.live_stats"] = nil
        live = require "core.live_stats"
    end)

    local function ctx(ip, ua, uri)
        return {
            request = { host = "h.example.com", remote_addr = ip or "1.2.3.4",
                        user_agent = ua or "UA", uri = uri or "/a.php" },
            get_uri_args = function() return {} end,
        }
    end

    it("folds a minute into the history and reads it back", function()
        local completed = CLOCK - (CLOCK % 60)
        for _ = 1, 4 do live.record(ctx("10.0.0.1", "UA", "/a.php")) end
        for i = 1, 3 do live.record(ctx("10.0.0." .. i, "UA", "/a.php")) end
        -- The timer fires after the minute has ended.
        CLOCK = completed + 60 + 5
        live.roll_history()

        local hist = live.history("h.example.com", 180)
        assert.are.equal(1, #hist, "one minute was folded")
        assert.are.equal(completed, hist[1].ts, "the completed minute was folded")
        assert.are.equal(7, hist[1].requests)
        assert.are.equal(3, hist[1].distinct_ips, "three distinct clients")
    end)

    it("does not fold the minute still in progress", function()
        -- Four requests land in minute A, then the timer fires in minute B
        -- with three more requests already recorded there. Folding the current
        -- minute would either write B's partial row or lose A entirely.
        local completed = CLOCK - (CLOCK % 60)
        for _ = 1, 4 do live.record(ctx("10.0.0.1", "UA", "/a.php")) end
        CLOCK = completed + 60 + 10
        for _ = 1, 3 do live.record(ctx("10.0.0.2", "UA", "/a.php")) end
        live.roll_history()

        local hist = live.history("h.example.com", 180)
        assert.are.equal(1, #hist)
        assert.are.equal(completed, hist[1].ts)
        assert.are.equal(4, hist[1].requests,
            "only the completed minute is folded, not the one in progress")
    end)

    it("does not fold the same minute twice", function()
        for _ = 1, 5 do live.record(ctx("10.0.0.1", "UA", "/a.php")) end
        CLOCK = CLOCK - (CLOCK % 60) + 60 + 5
        live.roll_history()
        -- A second callback in the same wall-clock minute (clock step or a
        -- delayed timer) must not add the minute to the hourly sum again.
        live.roll_history()

        local hours = live.hour_history("h.example.com", 168)
        assert.are.equal(1, #hours)
        assert.are.equal(5, hours[1].requests, "the hour row must not double count")
    end)

    it("keeps one key per host rather than one per minute", function()
        -- The namespace count is what made /dicts answer with 678 KB.
        for _ = 1, 3 do live.record(ctx("10.0.0.1", "UA", "/a.php")) end
        CLOCK = CLOCK - (CLOCK % 60) + 60 + 5
        live.roll_history()
        local n = 0
        local registry = false
        for k in pairs(shared._v) do
            -- `hist:hosts` is the ONE global registry of hosts that may hold
            -- history (HIST_HOST_LIMIT); the per-host series are `hist:<host>`
            -- and `histH:<host>`. Counting the registry as a per-host key
            -- would make the bound look like it grew with every host.
            if k == "hist:hosts" then
                registry = true
            elseif k:match("^hist:") or k:match("^histH:") then
                n = n + 1
            end
        end
        assert.is_true(n <= 2, "at most two history keys per host, got " .. n)
        assert.is_true(registry, "the host registry must exist")
    end)

    it("registers hosts in one key and honours the per-minute host list", function()
        -- HIST_HOST_LIMIT caps how many hosts may hold a series: the TTL
        -- bounds a key's LIFETIME but not the CARDINALITY inside one window,
        -- and a rotating Host header would otherwise fill the 20 MB zone.
        -- `_M.hosts(2)` draws from the per-minute list, which is itself
        -- capped at MAX_HOSTS_PER_MINUTE — so a single roll registers at
        -- most that many hosts, and the registry stays ONE key.
        local function ctx_host(host)
            return {
                request = { host = host, remote_addr = "10.0.0.1",
                            user_agent = "UA", uri = "/a.php" },
                get_uri_args = function() return {} end,
            }
        end
        for i = 1, 5 do
            local host = "h" .. i .. ".example.com"
            for _ = 1, 3 do live.record(ctx_host(host)) end
        end
        CLOCK = CLOCK - (CLOCK % 60) + 60 + 5
        live.roll_history()

        -- The registry is a single key, not one per host.
        local reg = shared._v["hist:hosts"] or ""
        local n = 0
        if reg ~= "" then n = select(2, reg:gsub(",", "")) + 1 end
        assert.equals(5, n, "the registry lists exactly the registered hosts")
        assert.is_true(#reg < 1024, "the registry must stay one bounded value")

        -- Every registered host has its two series.
        local series = 0
        for k in pairs(shared._v) do
            if k ~= "hist:hosts" and (k:match("^hist:") or k:match("^histH:")) then
                series = series + 1
            end
        end
        assert.equals(10, series, "5 hosts x (minute + hour) series")
    end)

    it("stops minting series for new hosts once the registry is full", function()
        -- Drive several rolls, each with a fresh batch of hosts, so the
        -- registry accumulates past HIST_HOST_LIMIT. Hosts beyond the cap
        -- must NOT get a series (that is what keeps a rotating Host header
        -- from filling the statistics dict).
        local function ctx_host(host)
            return {
                request = { host = host, remote_addr = "10.0.0.1",
                            user_agent = "UA", uri = "/a.php" },
                get_uri_args = function() return {} end,
            }
        end

        -- 3 batches of 200 hosts each (600 > HIST_HOST_LIMIT of 512).
        for batch = 1, 3 do
            for i = 1, 200 do
                live.record(ctx_host(string.format("b%d-h%03d.example.com", batch, i)))
            end
            CLOCK = CLOCK - (CLOCK % 60) + 60 + 5
            live.roll_history()
        end

        local reg = shared._v["hist:hosts"] or ""
        local registered = 0
        if reg ~= "" then registered = select(2, reg:gsub(",", "")) + 1 end
        assert.is_true(registered <= 512,
            "the registry must not exceed HIST_HOST_LIMIT, got " .. registered)

        local series = 0
        for k in pairs(shared._v) do
            if k ~= "hist:hosts" and (k:match("^hist:") or k:match("^histH:")) then
                series = series + 1
            end
        end
        -- Each registered host holds 2 series; a host beyond the cap holds
        -- none. So the series count tracks the registry, not the traffic.
        assert.equals(registered * 2, series,
            "only registered hosts may hold a series (registered=" .. registered ..
            ", series=" .. series .. ")")
    end)

    it("expires the per-host series (no TTL-less history keys)", function()
        for _ = 1, 3 do live.record(ctx("10.0.0.1", "UA", "/a.php")) end
        CLOCK = CLOCK - (CLOCK % 60) + 60 + 5
        live.roll_history()
        -- The series keys used to be written without a TTL, so every distinct
        -- Host header ever seen left a permanent key in the statistics dict
        -- (flush_expired cannot remove a TTL-less key).
        local expires = shared._e or {}
        local found_ttl = false
        for k, exp in pairs(expires) do
            if k:match("^hist:") or k:match("^histH:") or k == "hist:hosts" then
                found_ttl = true
                assert.is_truthy(exp > CLOCK, k .. " must expire in the future")
            end
        end
        assert.is_true(found_ttl, "the history keys must carry a TTL")
    end)

    it("accumulates a baseline over the history", function()
        -- A few minutes of a steady 10 requests a minute.
        for _ = 1, 3 do
            for i = 1, 10 do live.record(ctx("10.0.0." .. i, "UA", "/a.php")) end
            -- move past the minute being recorded, then fold it
            CLOCK = CLOCK - (CLOCK % 60) + 60 + 5
            live.roll_history()
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