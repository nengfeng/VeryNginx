-- vim: filetype=lua
--
-- The dashboard shows two numbers side by side under the same "today" label:
-- "今日标记" (stats.flagged_today) and "今日被标记 IP（含已过期）"
-- (stats.flagged_log). They drifted apart because they used different day
-- definitions: the counter was a 24h-TTL rolling value that ignores day
-- boundaries, while the list was keyed by the UTC calendar day. On a CST box
-- the UTC day rolls over at 08:00 local, so between local midnight and 08:00
-- every day the counter included events whose records had gone into the
-- previous day's bucket — seen as "今日标记 14" above a five-row table, the
-- other nine sitting in a bucket nobody displays.
--
-- The fix puts both on one day function and keys the counter by day, so no
-- rolling window is left to disagree with. These tests pin the two together
-- and pin the day to the server's LOCAL date.

describe("ip_reputation flagged_today / flagged_log day alignment", function()
    local rep

    setup(function()
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
        rep = require("core.ip_reputation")
    end)

    local local_day  = os.date("%Y%m%d")
    local utc_day    = os.date("!%Y%m%d")

    it("keys the counter by the LOCAL date, not the UTC one", function()
        assert.are.equal(os.date("%Y%m%d"), local_day)
        assert.is_not_nil(rep.get_stats().flagged_today)
        -- The regression guard: if these are equal the box is on UTC and the
        -- test cannot distinguish the two implementations — assert that the
        -- counter key exists under the local day spelling.
        local s = ngx.shared.ip_reputation
        rep.flag_ip("203.0.113.7", 600)
        local key = "ip_rep:flagged_today:" .. local_day
        assert.truthy(s:get(key) ~= nil,
            "counter key missing for the local day (" .. local_day .. ")")
    end)

    it("derives the counter key and the log index from the same day", function()
        local s = ngx.shared.ip_reputation
        rep.flag_ip("203.0.113.8", 600)
        local day_index = "ip_rep:flaglog:" .. local_day
        assert.truthy(s:get(day_index) ~= nil, "flag-log day index missing")
        assert.truthy(s:get("ip_rep:flagged_today:" .. local_day) ~= nil,
            "counter key missing")
        -- Never the previous UTC bucket: that is where the nine events hid.
        if local_day ~= utc_day then
            assert.is_nil(s:get("ip_rep:flaglog:" .. utc_day),
                "flag log written under the UTC day")
        end
    end)

    it("stats counter equals the log list length for one flag per IP", function()
        local s = ngx.shared.ip_reputation
        s:flush_all()
        rep.flag_ip("203.0.113.20", 600)
        rep.flag_ip("203.0.113.21", 600)
        rep.flag_ip("203.0.113.22", 600)
        local st = rep.get_stats()
        local log = st.flagged_log or {}
        assert.are.equal(3, st.flagged_today)
        assert.are.equal(3, #log)
        assert.are.equal(st.flagged_today, #log)
    end)

    it("a re-flag counts twice but lists once, and never inverts", function()
        local s = ngx.shared.ip_reputation
        s:flush_all()
        rep.flag_ip("203.0.113.30", 600)
        rep.clear_ip("203.0.113.30")
        rep.flag_ip("203.0.113.30", 600)
        local st = rep.get_stats()
        local log = st.flagged_log or {}
        assert.are.equal(2, st.flagged_today, "two new-flag events")
        assert.are.equal(1, #log, "one distinct IP")
        assert.are.equal(2, log[1].count, "per-IP count merged")
        assert.is_true(#log <= st.flagged_today,
            "the distinct-IP list must never exceed the event counter")
    end)

    it("the log entries all belong to the day the counter counts", function()
        local s = ngx.shared.ip_reputation
        s:flush_all()
        rep.flag_ip("203.0.113.40", 600)
        local st = rep.get_stats()
        local log = st.flagged_log or {}
        assert.are.equal(1, #log)
        assert.truthy(log[1].ip == "203.0.113.40")
        assert.truthy(log[1].first_at ~= nil and log[1].last_at ~= nil)
        assert.are.equal(st.flagged_today, #log)
    end)
end)
