-- -*- coding: utf-8 -*-
-- Tests for enforce promotion and canary.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.sleep = function() end

_G.ngx.shared = setmetatable({_cache = {}}, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v) st[k] = v; return true, nil end,
                add = function(_, k, v) if st[k] then return false, "exists" end; st[k] = v; return true, nil end,
                incr = function(_, k, d, i) if st[k] == nil then st[k] = (i or 0) end; st[k] = st[k] + d; return st[k], nil end,
                delete = function(_, k) st[k] = nil end,
                expire = function() end,
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
            }
        end
        return t._cache[name]
    end,
})

-- Mock ir (ip_reputation)
local ir = {
    is_flagged = function(ip) return ip == "203.0.113.10" end,
    is_whitelisted = function() return false end,
}
package.loaded["core.ip_reputation"] = ir

-- Mock evidence
local mock_evidence_data = {}
local mock_cc_violations = {}  -- ip -> count
local evidence = {
    sum_scanner_blocks = function(ip) return mock_evidence_data[ip] or 0 end,
    count_cc_violations = function(ip) return mock_cc_violations[ip] or 0 end,
    record_cc_violation_evidence = function() end,
    record_waf_block_evidence = function() end,
}
package.loaded["core.kernel_blocking.evidence"] = evidence

-- Mock config
local mock_config = {
    kernel_ip_blocking = {
        enabled = true,
        mode = "observe",
        topology = "direct",
        fail_policy = "open",
        ipv4 = { enabled = true },
        ipv6 = { enabled = false },
        scanner = { enabled = true, min_hard_blocks = 3, max_ttl = 86400 },
        cc = { enabled = true, enforce_ready = false, rule_ids = {"freq_rule_1"}, ttl = 300, max_ttl = 1800, min_violation_windows = 3, require_challenge_fail = false },
        promotion_rate_limit = { limit = 1000, interval = 60, burst = 1000 },
        canary = { scanner_ttl = 60, cc_ttl = 30 },
        emergency_pause = false,
    },
    ip_reputation = {},
}
package.loaded["core.config"] = { kernel_ip_blocking = mock_config.kernel_ip_blocking }

-- When config module's with function is called, return mock
package.loaded["core.config"] = setmetatable(mock_config, {
    __index = function(t, k) return rawget(t, k) end,
})

-- Override executor to always return mock (so tests don't need Helper)
local _real_executor = require "core.kernel_blocking.executor"
local _mock_exec = _real_executor.get_mock()
package.loaded["core.kernel_blocking.executor"] = {
    get_executor = function() return _mock_exec end,
    get_mock = function() return _mock_exec end,
}

local promotion = require "core.kernel_blocking.promotion"
local sm = require "core.kernel_blocking.state_machine"

describe("Enforce promotion", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
        ngx.shared.frequency_limit:flush_all()
        mock_config.kernel_ip_blocking.emergency_pause = false
        mock_config.kernel_ip_blocking.mode = "observe"
        mock_config.kernel_ip_blocking.cc.enforce_ready = false
        mock_evidence_data["203.0.113.10"] = 10  -- 10 hits, above min_hard_blocks
        mock_evidence_data["203.0.113.20"] = 1   -- below threshold
        mock_cc_violations["203.0.113.30"] = 5   -- satisfies min_violation_windows
        mock_cc_violations["203.0.113.40"] = 1   -- below threshold
    end)

    it("observe mode does NOT install (only logs)", function()
        mock_config.kernel_ip_blocking.mode = "observe"
        sm.upsert_candidate("203.0.113.10", "scanner", "observed",
            {}, { block_hits = 10, flagged = true })
        promotion.process_candidates(ngx.time())
        local e = sm.get("203.0.113.10")
        assert.are.equal("candidate", e.state)
    end)

    it("enforce mode installs via mock executor", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        sm.upsert_candidate("203.0.113.10", "scanner", "observed",
            {}, { block_hits = 10, flagged = true })
        promotion.process_candidates(ngx.time())
        local e = sm.get("203.0.113.10")
        assert.are.equal("installed", e.state)
        assert.are.equal("scanner_drop", e.list)
    end)

    it("enforce mode respects emergency_pause", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        mock_config.kernel_ip_blocking.emergency_pause = true
        sm.upsert_candidate("203.0.113.10", "scanner", "observed",
            {}, { block_hits = 10, flagged = true })
        promotion.process_candidates(ngx.time())
        local e = sm.get("203.0.113.10")
        assert.are.equal("candidate", e.state)
        assert.are.equal("paused", e.evidence.result)
    end)

    it("enforce mode rate-limited when observe token empty", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        ngx.shared.vn_locks:set("kb:observe_bucket:state",
            require("dkjson").encode({ tokens = 0, last_refill = ngx.time() * 1000 }), 3600)
        sm.upsert_candidate("203.0.113.10", "scanner", "observed",
            {}, { block_hits = 10, flagged = true })
        promotion.process_candidates(ngx.time())
        local e = sm.get("203.0.113.10")
        assert.are.equal("candidate", e.state)
        assert.are.equal("would_rate_limit", e.evidence.result)
    end)

    it("enforce mode requires strict threshold", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        sm.upsert_candidate("203.0.113.20", "scanner", "observed",
            {}, { block_hits = 1, flagged = false })
        promotion.process_candidates(ngx.time())
        local e = sm.get("203.0.113.20")
        assert.are.equal("candidate", e.state)
        assert.are.equal("would_not_promote", e.evidence.result)
    end)
end)

describe("CC promotion", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
        ngx.shared.frequency_limit:flush_all()
        mock_config.kernel_ip_blocking.emergency_pause = false
        mock_config.kernel_ip_blocking.mode = "observe"
        mock_config.kernel_ip_blocking.cc.enforce_ready = false
        mock_cc_violations["203.0.113.30"] = 5
        mock_cc_violations["203.0.113.40"] = 1
    end)

    it("observe mode does NOT install CC (only logs)", function()
        mock_config.kernel_ip_blocking.mode = "observe"
        sm.upsert_candidate("203.0.113.30", "cc", "observed",
            {}, { rule_id = "freq_rule_1" })
        promotion.process_candidates(ngx.time())
        local e = sm.get("203.0.113.30")
        assert.are.equal("candidate", e.state)
    end)

    it("enforce mode installs CC when violations >= min_windows", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        mock_config.kernel_ip_blocking.cc.enforce_ready = true
        sm.upsert_candidate("203.0.113.30", "cc", "observed",
            {}, { rule_id = "freq_rule_1" })
        promotion.process_candidates(ngx.time())
        local e = sm.get("203.0.113.30")
        assert.are.equal("installed", e.state)
        assert.are.equal("cc_drop", e.list)
    end)

    it("CC enforce_ready=false does NOT install even in enforce mode", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        mock_config.kernel_ip_blocking.cc.enforce_ready = false
        sm.upsert_candidate("203.0.113.30", "cc", "observed",
            {}, { rule_id = "freq_rule_1" })
        promotion.process_candidates(ngx.time())
        local e = sm.get("203.0.113.30")
        assert.are.equal("candidate", e.state)
    end)

    it("CC does NOT install when violations below threshold", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        mock_config.kernel_ip_blocking.cc.enforce_ready = true
        sm.upsert_candidate("203.0.113.40", "cc", "observed",
            {}, { rule_id = "freq_rule_1" })
        promotion.process_candidates(ngx.time())
        local e = sm.get("203.0.113.40")
        assert.are.equal("candidate", e.state)
        assert.are.equal("would_not_promote", e.evidence.result)
    end)

    it("CC respects emergency_pause", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        mock_config.kernel_ip_blocking.cc.enforce_ready = true
        mock_config.kernel_ip_blocking.emergency_pause = true
        sm.upsert_candidate("203.0.113.30", "cc", "observed",
            {}, { rule_id = "freq_rule_1" })
        promotion.process_candidates(ngx.time())
        local e = sm.get("203.0.113.30")
        assert.are.equal("candidate", e.state)
        assert.are.equal("paused", e.evidence.result)
    end)
end)

describe("Scanner/CC overlap", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
        ngx.shared.frequency_limit:flush_all()
        mock_config.kernel_ip_blocking.emergency_pause = false
        mock_config.kernel_ip_blocking.mode = "enforce"
        mock_config.kernel_ip_blocking.cc.enforce_ready = true
        mock_evidence_data["203.0.113.50"] = 10
        mock_cc_violations["203.0.113.50"] = 5
        -- Make is_flagged return true for the overlap test IP
        ir.is_flagged = function(ip) return ip == "203.0.113.10" or ip == "203.0.113.50" end
    end)

    it("CC does not install if IP already in scanner_drop", function()
        -- Pre-install in scanner_drop
        sm.upsert_candidate("203.0.113.50", "scanner", "installed",
            {}, { list = "scanner_drop" })
        -- Try CC promotion
        sm.upsert_candidate("203.0.113.50", "cc", "observed",
            {}, { rule_id = "freq_rule_1" })
        promotion.process_candidates(ngx.time())
        local e = sm.get("203.0.113.50")
        -- Should remain in scanner_drop, CC should be marked as already_in_scanner_drop
        assert.are.equal("scanner_drop", e.list)
    end)

    it("Scanner upgrade removes from cc_drop (overlap)", function()
        -- Pre-install in cc_drop
        sm.upsert_candidate("203.0.113.50", "cc", "installed",
            {}, { list = "cc_drop", expires_at = ngx.time() + 300 })
        -- Now scanner also triggers
        sm.upsert_candidate("203.0.113.50", "scanner", "observed",
            {}, { block_hits = 10, flagged = true })
        promotion.process_candidates(ngx.time())
        local e = sm.get("203.0.113.50")
        -- Should be upgraded to scanner_drop
        assert.are.equal("installed", e.state)
        assert.are.equal("scanner_drop", e.list)
    end)
end)
