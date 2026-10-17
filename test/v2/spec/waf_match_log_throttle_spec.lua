-- The per-match line in plugin/filter is the one WARN on the request path.
--
-- It was harmless while error_log ran at crit and nothing below crit was ever
-- written. Raising error_log to warn — which is what makes dict_guard's write
-- failures, the forced-eviction warnings and upstream errors visible at all —
-- turns it into a firehose: log-mode rules recorded 5154 hits in a single day
-- on this host, so one line per hit would bury the messages the level was
-- raised for. It is throttled per rule instead, with the suppressed count kept
-- so "is this rule still matching" stays answerable.

describe("log-mode rule match logging is bounded", function()
    local filter, LOGS, NOW

    setup(function()
        LOGS = {}
        NOW = 1700000000
        -- Only this one call is under test; capturing it separately from the
        -- ngx.log capture the shared helper installs keeps the assertions
        -- about throttle behaviour rather than about the harness.
        local real_log = ngx.log
        ngx.log = function(...)
            -- The level is the first argument and the spec rig leaves it nil,
            -- so flatten rather than concat.
            local parts = {}
            for i = 1, select("#", ...) do parts[#parts + 1] = tostring((select(i, ...))) end
            LOGS[#LOGS + 1] = table.concat(parts, "")
        end
        _G.TEST_RESTORE_LOG = function() ngx.log = real_log end

        filter = require "plugin.filter.init"
    end)

    teardown(function()
        if _G.TEST_RESTORE_LOG then _G.TEST_RESTORE_LOG() end
    end)

    local function log_rule_match()
        assert.is_truthy(filter._test_log_rule_match,
            "filter module must expose the throttled helper")
        return filter._test_log_rule_match
    end

    before_each(function()
        LOGS = {}
        NOW = 1700000000
        filter._test_match_log_reset(function() return NOW end)
    end)

    it("emits one line for the first match of a rule", function()
        log_rule_match()("vn_brute_0018", "wp-login brute")
        assert.are.equal(1, #LOGS, "the first match must be logged")
        assert.is_truthy(LOGS[1]:find("vn_brute_0018", 1, true))
    end)

    it("suppresses repeats inside the interval", function()
        local log = log_rule_match()
        log("vn_bot_0016", "phpMyAdmin")
        for _ = 1, 500 do log("vn_bot_0016", "phpMyAdmin") end
        assert.are.equal(1, #LOGS,
            "500 matches inside one window must not become 500 lines")
    end)

    it("logs again after the interval and reports what it dropped", function()
        local log = log_rule_match()
        log("vn_ssrf_0021", "soap")
        for _ = 1, 42 do log("vn_ssrf_0021", "soap") end
        NOW = NOW + 61
        log("vn_ssrf_0021", "soap")
        assert.are.equal(2, #LOGS, "the window must reopen")
        assert.is_truthy(LOGS[2]:find("42", 1, true),
            "the suppressed count has to stay visible: " .. LOGS[2])
    end)

    it("budgets per rule, not globally", function()
        local log = log_rule_match()
        for i = 1, 50 do log("rule_a_" .. i, "x") end
        assert.are.equal(50, #LOGS, "50 distinct rules must each get a line")
    end)
end)