-- -*- coding: utf-8 -*-
-- Live traffic shape: the dimensions the panel could not show.
--
-- The statistics engine counts requests per (bucket, host, uri). It could not
-- answer, during the 2026-10 incident:
--
--   * how many DISTINCT clients are hitting us, and how many requests each one
--     makes (a normal forum is ~0.2 per client; the scraper that took the site
--     down was 1.01, from 3,662 addresses in five minutes);
--   * what the traffic LOOKS like — UA family, path shape, cookie, referer;
--   * what the BACKEND returned. 99.4% of inbound requests ended in 499/502
--     and 429/499/504 were not even in the recorded status set.
--
-- These tests pin the collection behaviour, the bounded-ness (the statistics
-- dict already taught us what unbounded looks like: 9,848 keys, 7,272
-- namespaces, a 678 KB /dicts response), and the shape normalisation that
-- makes a rotating scraper visible as one shape.

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

describe("live traffic shape collection", function()

    local shared, live, stats
    -- Fixed clock: the live view keys everything by minute, so a test that
    -- straddles a minute boundary would be flaky.
    local CLOCK = 1700000000

    setup(function()
        if not _G.ngx then _G.ngx = {} end
        _G.ngx.log = _G.ngx.log or function() end
        _G.ngx.now = _G.ngx.now or function() return os.time() end
        _G.ngx.time = _G.ngx.time or function() return os.time() end
        _G.ngx.crc32_long = _G.ngx.crc32_long or function(s)
            local h = 5381
            for i = 1, #s do h = (h * 33 + s:byte(i)) % 4294967296 end
            return h
        end
        _G.ngx.var = { http_cookie = nil, http_referer = nil }
        _G.ngx.shared = setmetatable({}, {
            __index = function(_, name)
                local d = make_shared()
                rawset(_G.ngx.shared, name, d)
                return d
            end,
        })
        package.loaded["core.live_stats"] = nil
        package.loaded["core.statistics"] = nil
        live = require "core.live_stats"
        stats = require "core.statistics"
    end)

    teardown(function()
        package.loaded["core.live_stats"] = nil
        package.loaded["core.statistics"] = nil
    end)

    -- setup() runs ONCE per describe, so the shared dict has to be reset per
    -- test or the shapes recorded by an earlier test are still in the list and
    -- every count comes out too high.
    before_each(function()
        for k in pairs(_G.ngx.shared) do rawset(_G.ngx.shared, k, nil) end
        _G.ngx.var.http_cookie = nil
        _G.ngx.var.http_referer = nil
        -- Pin the clock for this describe: the module keys by minute, and a
        -- real clock can step over a boundary mid-test.
        _G.ngx.now = function() return CLOCK end
        _G.ngx.time = function() return CLOCK end
    end)

    local function ctx(ip, ua, uri, args, cookie, referer)
        _G.ngx.var.http_cookie = cookie
        _G.ngx.var.http_referer = referer
        return {
            request = { host = "www.example.com", remote_addr = ip or "1.2.3.4",
                        user_agent = ua or "UA", uri = uri or "/x.php" },
            get_uri_args = function() return args or {} end,
        }
    end

    -- Same shape as ctx(), but with an arbitrary Host header.
    local function ctx_host(host, ip)
        _G.ngx.var.http_cookie = nil
        _G.ngx.var.http_referer = nil
        return {
            request = { host = host, remote_addr = ip or "1.2.3.4",
                        user_agent = "UA", uri = "/a.php" },
            get_uri_args = function() return {} end,
        }
    end

    it("counts a distinct client set and the requests each made", function()
        -- The number the panel needs: distinct clients, and how many requests
        -- per client. A normal visitor repeats; a scraper that rotates its
        -- address does not.
        for _ = 1, 5 do live.record(ctx("10.0.0.1", "UA", "/a.php")) end
        for i = 1, 5 do live.record(ctx("10.0.0." .. i, "UA", "/a.php")) end

        local series = live.host_series("www.example.com", 1)
        assert.are.equal(1, #series)
        local s = series[1]
        assert.are.equal(10, s.requests, "every recorded request is counted")
        -- 10.0.0.1 appears in both loops, so five distinct clients, not six.
        assert.are.equal(5, s.distinct_ips, "five distinct clients were seen")
        assert.are.equal(2, s.req_per_ip,
            "ten requests over five clients is two requests each")
    end)

    it("separates a repeating client from many single-request clients", function()
        for _ = 1, 10 do live.record(ctx("10.0.0.1", "UA", "/a.php")) end
        local one = live.host_series("www.example.com", 1)[1]
        assert.are.equal(1, one.distinct_ips)
        assert.are.equal(10, one.req_per_ip)

        -- Now the same request volume from ten different addresses.
        shared = make_shared()
        rawset(_G.ngx.shared, "statistics", shared)
        package.loaded["core.live_stats"] = nil
        live = require "core.live_stats"
        for i = 1, 10 do live.record(ctx("10.0.0." .. i, "UA", "/a.php")) end
        local many = live.host_series("www.example.com", 1)[1]
        assert.are.equal(10, many.distinct_ips)
        assert.are.equal(1, many.req_per_ip,
            "one request per client is the distributed-scraper signature")
    end)

    it("collapses a rotating user agent into one shape", function()
        -- The scraper rotated Chrome/142 .. Chrome/145. Normalising the digits
        -- makes that ONE shape with a large count, which is the thing worth
        -- noticing. Without it, the panel would show 25 shapes of equal size
        -- and look like normal traffic.
        for _, v in ipairs({ "142", "143", "144", "145" }) do
            live.record(ctx("10.0.0." .. #v, "Mozilla/5.0 Chrome/" .. v .. ".0.0.0 Safari/537.36", "/a.php"))
        end
        local s = live.host_series("www.example.com", 1)[1]
        assert.are.equal(1, #s.shapes, "four Chrome versions are one shape")
        assert.are.equal(4, s.shapes[1].count)
        assert.is_truthy(s.shapes[1].shape:find("Chrome/%*"), "the shape is normalised: " .. s.shapes[1].shape)
    end)

    it("keeps different path shapes apart and merges the same one", function()
        live.record(ctx("1.1.1.1", "UA", "/search.php", { search_id = "unanswered" }))
        live.record(ctx("1.1.1.2", "UA", "/search.php", { search_id = "active_topics" }))
        live.record(ctx("1.1.1.3", "UA", "/ucp.php", { mode = "privacy" }))
        local s = live.host_series("www.example.com", 1)[1]
        -- Two shapes: search.php?search_id=* and ucp.php?mode=*
        assert.are.equal(2, #s.shapes)
        local counts = {}
        for _, sh in ipairs(s.shapes) do counts[sh.shape] = sh.count end
        for shape, n in pairs(counts) do
            if shape:find("search.php") then
                assert.are.equal(2, n, "the two searches share a shape")
            end
        end
    end)

    it("records whether the request carried a cookie or a referer", function()
        live.record(ctx("1.1.1.1", "UA", "/a.php", {}, nil, nil))
        live.record(ctx("1.1.1.2", "UA", "/a.php", {}, "sid=abc", "https://ref"))
        local s = live.host_series("www.example.com", 1)[1]
        assert.are.equal(2, #s.shapes, "cookie and referer presence separate the shapes")
        local with_cookie = 0
        for _, sh in ipairs(s.shapes) do
            if sh.shape:find("c1") then with_cookie = with_cookie + 1 end
        end
        assert.are.equal(1, with_cookie, "exactly one shape carried a cookie")
    end)

    it("records when a shape was first seen", function()
        live.record(ctx("1.1.1.1", "UA", "/a.php"))
        local s = live.host_series("www.example.com", 1)[1]
        assert.is_truthy(s.shapes[1].first_seen, "first_seen must be recorded")
        assert.is_true(s.shapes[1].first_seen <= CLOCK)
    end)

    it("bounds the number of shapes it keeps", function()
        -- The statistics dict ballooned to 7,272 namespaces before; a new
        -- collector must not repeat that.
        for i = 1, 200 do
            live.record(ctx("1.1.1." .. (i % 250), "UA" .. i, "/p" .. i .. ".php"))
        end
        local s = live.host_series("www.example.com", 1)[1]
        assert.is_true(#s.shapes <= 32,
            "at most 32 shapes may be kept, got " .. #s.shapes)
    end)

    it("bounds the IP sample", function()
        -- A fixed-size sample, not a set: the sample is 256 slots regardless
        -- of how many clients arrive.
        for i = 1, 600 do
            live.record(ctx("10.0." .. math.floor(i / 256) .. "." .. (i % 256), "UA", "/a.php"))
        end
        local s = live.host_series("www.example.com", 1)[1]
        assert.is_true(s.distinct_ips <= 256,
            "the sample cannot exceed its slots, got " .. s.distinct_ips)
        assert.is_true(s.sample_full, "and it must say when the sample filled up")
    end)

    it("lists the hosts that had traffic", function()
        live.record(ctx("1.1.1.1", "UA", "/a.php"))
        local hosts = live.hosts(5)
        local found = false
        for _, h in ipairs(hosts) do
            if h == "www.example.com" then found = true end
        end
        assert.is_true(found, "the host must be listed")
    end)

    it("normalizes the Host header before it becomes a dict key", function()
        -- The raw header is case-preserving and may carry a trailing root dot.
        -- The statistics engine normalizes it; the live view must agree, or the
        -- panel would show "WWW.Example.COM." and its history would never line
        -- up with the per-host statistics.
        live.record(ctx_host("WWW.Example.COM.", "10.0.0.1"))
        local series = live.host_series("www.example.com", 1)
        assert.are.equal(1, #series, "the normalized host has the data")
        assert.are.equal(1, series[1].requests)
        assert.are.equal("www.example.com", live.hosts(1)[1])
    end)

    it("does not hide a host that is a substring of an earlier one", function()
        -- Membership used to be a plain substring test, so "example.com" was
        -- considered already present after "www.example.com", and it silently
        -- vanished from the host list (and therefore from history).
        live.record(ctx_host("www.example.com", "10.0.0.1"))
        live.record(ctx_host("example.com", "10.0.0.2"))
        local found = {}
        for _, h in ipairs(live.hosts(1)) do found[h] = true end
        assert.is_true(found["www.example.com"])
        assert.is_true(found["example.com"],
            "a host must not be dropped just because it is a substring")
        assert.is_truthy(live.host_series("example.com", 1)[1],
            "and its minute data must be readable")
    end)

    it("a comma in the Host header cannot forge host-list entries", function()
        -- "," is the list separator. Unnormalized, one request with
        -- "evil.example,other.example" invented two hosts in the panel.
        live.record(ctx_host("evil.example,other.example", "10.0.0.1"))
        local hosts = live.hosts(1)
        assert.are.equal(1, #hosts, "one request is one host: " .. #hosts)
        for _, h in ipairs(hosts) do
            assert.are_not.equal("evil.example", h)
            assert.are_not.equal("other.example", h)
        end
        assert.are.equal("evil.example_other.example", hosts[1],
            "the comma is normalized into the single key")
    end)

    it("caps how many hosts one minute can create", function()
        -- A rotating Host header must not be able to fill the 20 MB
        -- statistics dict with lm: namespaces by LRU-evicting real data.
        for i = 1, 400 do
            live.record(ctx_host("h" .. i .. ".example", "10.0.0.1"))
        end
        local hosts = live.hosts(1)
        assert.is_true(#hosts <= 256,
            "the per-minute host list is bounded, got " .. #hosts)
    end)
end)