-- -*- coding: utf-8 -*-
-- Tests for lifecycle generations, preserve_only, readiness matrix, status API.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7; _G.ngx.NOTICE = 8
_G.ngx.time = function() return 1700000000 end
_G.ngx.md5 = function(s) return "md5:" .. tostring(#s) end
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

local mock_config = {
    kernel_ip_blocking = {
        enabled = true,
        mode = "enforce",
        topology = "direct",
        fail_policy = "open",
        emergency_pause = false,
        ipv4 = { enabled = true },
        ipv6 = { enabled = false },
        scanner = { enabled = true, min_hard_blocks = 3, max_ttl = 86400 },
        cc = {
            enabled = true, enforce_ready = false, rule_ids = {"freq_rule_1"},
            ttl = 300, max_ttl = 1800,
        },
    },
    rule = { frequency_limit = { { id = "freq_rule_1", key = "ip", limit = 10, window = 60 } } },
}
package.loaded["core.config"] = setmetatable(mock_config, {
    __index = function(t, k) return rawget(t, k) end,
})

package.loaded["core.audit"] = { log = function() end }
package.loaded["core.metrics"] = {
    incr = function() end,
    gauge = function() end,
}

local lifecycle = require "core.kernel_blocking.lifecycle"
local readiness = require "core.kernel_blocking.readiness"
local desired = require "core.kernel_blocking.desired_state"
local sm = require "core.kernel_blocking.state_machine"
local mock = require "core.kernel_blocking.executor_mock"
package.loaded["core.kernel_blocking.executor"] = {
    get_executor = function() return mock end,
    get_mock = function() return mock end,
}
local recon = require "core.kernel_blocking.reconciliation"
local kb = require "core.kernel_blocking.init"

describe("Lifecycle transitions", function()
    before_each(function()
        ngx.shared.vn_locks:flush_all()
        ngx.shared.vn_config:flush_all()
        lifecycle.ensure_initialized()
        mock_config.kernel_ip_blocking.enabled = true
        mock_config.kernel_ip_blocking.mode = "enforce"
        mock_config.kernel_ip_blocking.cc.enforce_ready = false
    end)

    it("bumps global generation and preserve_only on disable", function()
        desired.set_desired("203.0.113.1", "ipv4", "scanner_drop", {}, 600, {
            source = "automatic", policy = "scanner", reconciliation_mode = "ensure",
        })
        sm.upsert("203.0.113.1", "scanner", "installed", {}, {
            list = "scanner_drop", family = "ipv4", expires_at = ngx.time() + 600,
            source = "automatic",
        })
        local old = { kernel_ip_blocking = {
            enabled = true, mode = "enforce", topology = "direct",
            scanner = { enabled = true }, cc = { enabled = true, enforce_ready = false, rule_ids = {"freq_rule_1"} },
            ipv4 = { enabled = true }, ipv6 = { enabled = false },
        } }
        local new = { kernel_ip_blocking = {
            enabled = false, mode = "enforce", topology = "direct",
            scanner = { enabled = true }, cc = { enabled = true, enforce_ready = false, rule_ids = {"freq_rule_1"} },
            ipv4 = { enabled = true }, ipv6 = { enabled = false },
        } }
        local st, reasons = lifecycle.on_config_activated(old, new)
        assert.truthy(st.global_activation_generation >= 2)
        local d = desired.get_desired("203.0.113.1", "ipv4", "scanner_drop")
        assert.truthy(d)
        assert.are.equal("preserve_only", d.reconciliation_mode)
        assert.truthy(#reasons > 0)
    end)

    it("evidence_allowed rejects pre-cutoff timestamps", function()
        local st = lifecycle.get_state()
        st.evidence_not_before = ngx.time() + 10
        lifecycle.set_state(st)
        local ok, why = lifecycle.evidence_allowed("scanner", ngx.time())
        assert.is_false(ok)
        assert.are.equal("global_cutoff", why)
    end)
end)

describe("Readiness matrix", function()
    before_each(function()
        ngx.shared.vn_locks:flush_all()
        ngx.shared.vn_config:flush_all()
        ngx.shared.frequency_limit:flush_all()
        mock_config.kernel_ip_blocking.enabled = true
        mock_config.kernel_ip_blocking.mode = "enforce"
        mock_config.kernel_ip_blocking.cc.enforce_ready = false
        mock_config.kernel_ip_blocking.topology = "direct"
    end)

    it("CC stays observe when enforce_ready=false in global enforce", function()
        local m = readiness.compute({ health = { state = "ok" } })
        assert.are.equal("enforce", m.effective.global_mode)
        assert.are.equal("observe", m.effective.cc.mode)
        assert.is_false(m.effective.cc.install_reachable)
        local found = false
        for _, r in ipairs(m.effective.cc.reason_codes) do
            if r == "cc_not_enforce_ready" then found = true end
        end
        assert.is_true(found)
    end)

    it("global disabled with active auto entries emits warning reason", function()
        mock_config.kernel_ip_blocking.enabled = false
        local m = readiness.compute({
            health = { state = "ok" },
            active_auto_entries = 2,
        })
        assert.are.equal("disabled", m.effective.global_mode)
        local found = false
        for _, r in ipairs(m.effective.reason_codes) do
            if r == "disabled_with_active_entries" then found = true end
        end
        assert.is_true(found)
    end)
end)

describe("Reconcile preserve_only", function()
    before_each(function()
        mock.flush_owned("all")
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
        mock_config.kernel_ip_blocking.enabled = true
        mock_config.kernel_ip_blocking.mode = "enforce"
    end)

    it("does not re-add missing preserve_only entries", function()
        -- Scope binding must be validated before DROP reconcile apply path.
        mock.ensure_base(mock_config.kernel_ip_blocking)
        desired.set_desired("198.51.100.9", "ipv4", "scanner_drop", {}, 300, {
            source = "automatic", policy = "scanner", reconciliation_mode = "preserve_only",
        })
        local r = recon.reconcile(ngx.time())
        assert.are.equal(0, r.applied_add)
        assert.truthy((r.skipped_preserve or 0) >= 1)
        local ok = mock.contains("scanner_drop", "ipv4", "198.51.100.9")
        assert.is_false(ok)
    end)
end)

describe("Status facade", function()
    before_each(function()
        mock.flush_owned("all")
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
        mock_config.kernel_ip_blocking.enabled = true
        mock_config.kernel_ip_blocking.mode = "observe"
    end)

    it("returns effective matrix and counters", function()
        sm.upsert("203.0.113.55", "scanner", "candidate", { block_hits = 2 }, {})
        local st = kb.status()
        assert.truthy(st.effective)
        assert.are.equal("observe", st.effective.global_mode)
        assert.truthy(st.counters)
        assert.are.equal(1, st.counters.candidates)
        assert.truthy(st.lifecycle)
        assert.truthy(st.promotion_bucket)
        assert.truthy(st.scheduler_leases)
        assert.truthy(st.scheduler_leases.batch)
        assert.is_false(st.scheduler_leases.batch.held == true)
        assert.is_false(st.scheduler_leases.reconcile.held == true)
    end)
end)

describe("Scheduler leases", function()
    before_each(function()
        mock.flush_owned("all")
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
        mock_config.kernel_ip_blocking.enabled = true
        mock_config.kernel_ip_blocking.mode = "enforce"
    end)

    it("reconcile single-flight skips when lease held", function()
        local held = {
            token = "held-by-test",
            worker_id = 0,
            acquired_at = ngx.time(),
            ttl = 60,
            name = "kb:lease:reconcile",
        }
        local json = require "dkjson"
        ngx.shared.vn_locks:add("kb:lease:reconcile", json.encode(held), 60)
        local r = kb.reconcile(ngx.time())
        assert.are.equal("lease_busy", r.skipped)
        local st = kb.lease_status()
        assert.is_true(st.reconcile.held)
    end)

    it("batch single-flight skips when lease held", function()
        local json = require "dkjson"
        ngx.shared.vn_locks:add("kb:lease:batch", json.encode({
            token = "held-batch", worker_id = 0, acquired_at = ngx.time(), ttl = 30,
        }), 30)
        local r = kb.process_candidates(ngx.time())
        assert.are.equal("lease_busy", r.skipped)
    end)

    it("dispatch single-flight skips when lease held", function()
        local json = require "dkjson"
        ngx.shared.vn_locks:add("kb:lease:dispatch", json.encode({
            token = "held-dispatch", worker_id = 0, acquired_at = ngx.time(), ttl = 30,
        }), 30)
        local r = kb.flush_dispatch_queue(ngx.time())
        assert.are.equal("lease_busy", r.skipped)
    end)

    it("releases reconcile lease after success so next call proceeds", function()
        mock.ensure_base(mock_config.kernel_ip_blocking)
        local r1 = kb.reconcile(ngx.time())
        assert.truthy(r1.skipped ~= "lease_busy")
        local r2 = kb.reconcile(ngx.time())
        assert.truthy(r2.skipped ~= "lease_busy")
        assert.is_false(kb.lease_status().reconcile.held == true)
    end)
end)
