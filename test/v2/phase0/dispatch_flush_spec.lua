-- -*- coding: utf-8 -*-
-- P2-11: bounded dispatch settle/requeue pass (Design §8.1/§10.1/§15.1).
-- flush_dispatch_queue must report the real stuck depth (dispatch_pending +
-- degraded) and settle/requeue stranded entries instead of returning a
-- hardcoded depth = 0 stub.

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
                incr = function(_, k, d, i)
                    if st[k] == nil then st[k] = (i or 0) end
                    st[k] = st[k] + d
                    return st[k], nil
                end,
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
    is_flagged = function() return false end,
    is_whitelisted = function() return false end,
}
package.loaded["core.ip_reputation"] = ir

-- Mock evidence (no live signal: requeued entries stay candidate)
local evidence = {
    sum_scanner_blocks = function() return 0 end,
    count_cc_violations = function() return 0 end,
    record_cc_violation_evidence = function() end,
    record_waf_block_evidence = function() end,
    has_challenge_fail = function() return false end,
    record_challenge_fail_evidence = function() end,
}
package.loaded["core.kernel_blocking.evidence"] = evidence

local mock_config = {
    kernel_ip_blocking = {
        enabled = true,
        mode = "enforce",
        topology = "direct",
        fail_policy = "open",
        ipv4 = { enabled = true },
        ipv6 = { enabled = false },
        scanner = { enabled = true, min_hard_blocks = 3, max_ttl = 86400 },
        cc = {
            enabled = true, enforce_ready = true, rule_ids = {"freq_rule_1"},
            ttl = 300, max_ttl = 1800, min_violation_windows = 3,
            require_challenge_fail = false,
        },
        promotion_rate_limit = { limit = 1000, interval = 60, burst = 1000 },
        emergency_pause = false,
    },
    ip_reputation = {},
}
package.loaded["core.config"] = setmetatable(mock_config, {
    __index = function(t, k) return rawget(t, k) end,
})

package.loaded["core.audit"] = { log = function() end }
package.loaded["core.metrics"] = { incr = function() end, gauge = function() end }

-- Mock executor: scope binding is auto-validated by ensure_base.
local mock = require "core.kernel_blocking.executor_mock"
package.loaded["core.kernel_blocking.executor"] = {
    get_executor = function() return mock end,
    get_mock = function() return mock end,
}

local sm = require "core.kernel_blocking.state_machine"
local kb = require "core.kernel_blocking.init"
local sb = require "core.kernel_blocking.scope_binding"

describe("Dispatch flush (P2-11)", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
        mock_config.kernel_ip_blocking.enabled = true
        mock_config.kernel_ip_blocking.mode = "enforce"
        mock_config.kernel_ip_blocking.emergency_pause = false
        mock_config.kernel_ip_blocking.cc.enforce_ready = true
        mock.ensure_base(mock_config.kernel_ip_blocking)
    end)

    it("requeues a valid dispatch_pending entry to candidate and reports depth", function()
        sm.upsert("203.0.113.1", "scanner", "dispatch_pending", { result = "dispatched" }, {
            list = "scanner_drop",
            family = "ipv4",
            expires_at = ngx.time() + 300,
        })
        local r = kb.flush_dispatch_queue(ngx.time())
        assert.is_true(r.ok)
        assert.are.equal(1, r.depth)
        assert.are.equal(1, r.requeued)
        local e = sm.get("203.0.113.1")
        assert.are.equal("candidate", e.state)
        assert.are.equal("dispatch_requeued", e.evidence.result)
    end)

    it("requeues a degraded cc entry to candidate with degraded_requeued marker", function()
        sm.upsert("203.0.113.2", "cc", "degraded", { result = "exec_error" }, {
            list = "cc_drop",
            family = "ipv4",
            expires_at = ngx.time() + 300,
        })
        local r = kb.flush_dispatch_queue(ngx.time())
        assert.is_true(r.ok)
        assert.are.equal(1, r.depth)
        assert.are.equal(1, r.requeued)
        local e = sm.get("203.0.113.2")
        assert.are.equal("candidate", e.state)
        assert.are.equal("degraded_requeued", e.evidence.result)
    end)

    it("settles a stale approval (expires_at in the past) as expired", function()
        sm.upsert("203.0.113.3", "scanner", "dispatch_pending", {}, {
            list = "scanner_drop",
            family = "ipv4",
            expires_at = ngx.time() - 1,
        })
        local r = kb.flush_dispatch_queue(ngx.time())
        assert.is_true(r.ok)
        assert.are.equal(0, r.requeued)
        assert.are.equal(1, r.settled)
        local e = sm.get("203.0.113.3")
        assert.are.equal("expired", e.state)
        assert.are.equal("dispatch_stale", e.evidence.result)
    end)

    it("settles a security-gate failure as rejected", function()
        sm.upsert("127.0.0.1", "scanner", "degraded", {}, {
            list = "scanner_drop",
            family = "ipv4",
        })
        local r = kb.flush_dispatch_queue(ngx.time())
        assert.is_true(r.ok)
        assert.are.equal(1, r.settled)
        assert.are.equal(0, r.requeued)
        local e = sm.get("127.0.0.1", "scanner")
        assert.are.equal("rejected", e.state)
        assert.are.equal("loopback", e.evidence.reason)
    end)

    it("leaves manual-policy entries untouched (pipeline owns scanner/cc only)", function()
        sm.upsert("198.51.100.9", "manual", "dispatch_pending", {}, {
            list = "manual_drop",
            family = "ipv4",
        })
        local r = kb.flush_dispatch_queue(ngx.time())
        assert.is_true(r.ok)
        assert.are.equal(0, r.requeued)
        assert.are.equal(0, r.settled)
        local e = sm.get("198.51.100.9", "manual")
        assert.are.equal("dispatch_pending", e.state)
    end)

    it("skips the sweep while the protected scope is invalidated (retry-wait)", function()
        sm.upsert("203.0.113.4", "scanner", "dispatch_pending", {}, {
            list = "scanner_drop",
            family = "ipv4",
            expires_at = ngx.time() + 300,
        })
        sb.invalidate("test_invalidation")
        local r = kb.flush_dispatch_queue(ngx.time())
        assert.is_true(r.ok)
        assert.are.equal("scope_invalid", r.skipped)
        assert.are.equal(1, r.depth)
        local e = sm.get("203.0.113.4")
        assert.are.equal("dispatch_pending", e.state)
    end)

    it("skips the sweep when kernel_ip_blocking is disabled", function()
        mock_config.kernel_ip_blocking.enabled = false
        local r = kb.flush_dispatch_queue(ngx.time())
        assert.is_true(r.ok)
        assert.are.equal("disabled", r.skipped)
    end)

    it("bounds one flush at the mutation cap and defers the rest", function()
        for i = 1, 65 do
            local ip = string.format("198.51.100.%d", i)
            sm.upsert(ip, "scanner", "dispatch_pending", {}, {
                list = "scanner_drop",
                family = "ipv4",
                expires_at = ngx.time() + 300,
            })
        end
        local r = kb.flush_dispatch_queue(ngx.time())
        assert.is_true(r.ok)
        assert.are.equal(65, r.depth)
        assert.are.equal(64, r.requeued)
        -- Exactly one entry stays stranded for the next cycle.
        assert.are.equal(1, sm.count("dispatch_pending"))
    end)

    it("reports the real stuck depth in status dispatch_queue", function()
        sm.upsert("203.0.113.5", "scanner", "dispatch_pending", {}, { list = "scanner_drop" })
        sm.upsert("203.0.113.6", "scanner", "degraded", {}, { list = "scanner_drop" })
        sm.upsert("203.0.113.7", "cc", "dispatch_pending", {}, { list = "cc_drop" })
        local st = kb.status()
        assert.are.equal(3, st.dispatch_queue.depth)
        assert.are.equal(2, st.dispatch_queue.dispatch_pending)
        assert.are.equal(1, st.dispatch_queue.degraded)
    end)

    it("reports empty depth when nothing is stuck", function()
        local r = kb.flush_dispatch_queue(ngx.time())
        assert.is_true(r.ok)
        assert.are.equal(0, r.depth)
        assert.are.equal(0, r.requeued)
        assert.are.equal(0, r.settled)
    end)
end)
