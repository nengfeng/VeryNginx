-- -*- coding: utf-8 -*-
-- Tests for Phase 2/4: desired state wiring + reconciliation apply.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5
_G.ngx.INFO = 7
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

local mock_config = {
    kernel_ip_blocking = {
        enabled = true,
        mode = "observe",
        topology = "direct",
        fail_policy = "open",
        ipv4 = { enabled = true },
        ipv6 = { enabled = false },
        scanner = { enabled = true, min_hard_blocks = 3, max_ttl = 86400 },
        cc = { enabled = true, enforce_ready = true, rule_ids = {"r1"}, ttl = 300, max_ttl = 1800 },
        emergency_pause = false,
    },
}
package.loaded["core.config"] = mock_config

local mock = require "core.kernel_blocking.executor_mock"
package.loaded["core.kernel_blocking.executor"] = {
    get_executor = function() return mock end,
    get_mock = function() return mock end,
}

-- Promotion deps must be mocked before first require of promotion.
package.loaded["core.ip_reputation"] = {
    is_flagged = function(ip) return ip == "203.0.113.10" end,
    is_whitelisted = function() return false end,
}
package.loaded["core.kernel_blocking.evidence"] = {
    sum_scanner_blocks = function(ip)
        if ip == "203.0.113.10" then return 10 end
        return 0
    end,
    count_cc_violations = function() return 0 end,
}

local desired = require "core.kernel_blocking.desired_state"
local reconcil = require "core.kernel_blocking.reconciliation"
local sm = require "core.kernel_blocking.state_machine"
local promotion = require "core.kernel_blocking.promotion"

describe("Executor mock contract", function()
    before_each(function()
        mock.flush_owned("all")
        ngx.shared.vn_config:flush_all()
    end)

    it("probe returns capabilities", function()
        local caps = mock.probe()
        assert.truthy(caps)
        assert.are.equal(1, caps.protocol_min)
    end)

    it("add + contains + list + delete", function()
        mock.add("scanner_drop", "ipv4", "203.0.113.1", 3600)
        local ok, _ = mock.contains("scanner_drop", "ipv4", "203.0.113.1")
        assert.is_true(ok)
        local page = mock.list("scanner_drop", "ipv4", 0)
        assert.are.equal(1, #page.entries)
        mock.delete("scanner_drop", "ipv4", "203.0.113.1")
        ok, _ = mock.contains("scanner_drop", "ipv4", "203.0.113.1")
        assert.is_false(ok)
    end)

    it("flush_owned removes all entries", function()
        mock.add("scanner_drop", "ipv4", "10.0.0.1", 0)
        mock.add("cc_drop", "ipv4", "10.0.0.2", 0)
        local r = mock.flush_owned("all")
        assert.are.equal(2, r.removed)
    end)

    it("reconcile computes add/update/remove", function()
        mock.add("scanner_drop", "ipv4", "10.0.0.1", 0)
        local snap = {}
        local k = "kb_mock:nft:scanner_drop:ipv4:10.0.0.2"
        snap[k] = {
            set = "scanner_drop", family = "ipv4", ip = "10.0.0.2", ttl = 3600,
        }
        local result = mock.reconcile(snap)
        assert.are.equal(1, result.added)
        assert.are.equal(1, result.removed)
    end)

    it("health returns ok status", function()
        local h = mock.health()
        assert.are.equal("ok", h.state)
    end)
end)

describe("Desired state", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
    end)

    it("set + get desired entry", function()
        desired.set_desired("203.0.113.5", "ipv4", "scanner_drop",
            { block_hits = 5 }, 86400)
        local e = desired.get_desired("203.0.113.5", "ipv4", "scanner_drop")
        assert.truthy(e)
        assert.are.equal("203.0.113.5", e.ip)
        assert.are.equal("scanner_drop", e.list)
        assert.are.equal("promoted", e.dry_run_state)
    end)

    it("list desired paginates", function()
        for i = 1, 3 do
            desired.set_desired("10.0.0." .. i, "ipv4", "scanner_drop", {}, 0)
        end
        local page = desired.list_desired(0, 2)
        assert.are.equal(2, #page.entries)
        assert.truthy(page.next_cursor)
    end)

    it("count desired", function()
        assert.are.equal(0, desired.count_desired())
        desired.set_desired("10.0.0.1", "ipv4", "scanner_drop", {}, 0)
        assert.are.equal(1, desired.count_desired())
    end)

    it("remove_desired and clear_for_ip", function()
        desired.set_desired("10.0.0.9", "ipv4", "scanner_drop", {}, 60)
        desired.set_desired("10.0.0.9", "ipv4", "cc_drop", {}, 60)
        assert.are.equal(2, desired.count_desired())
        desired.remove_desired("10.0.0.9", "ipv4", "cc_drop")
        assert.are.equal(1, desired.count_desired())
        desired.clear_for_ip("10.0.0.9")
        assert.are.equal(0, desired.count_desired())
    end)
end)

describe("Reconciliation dry-run and apply", function()
    before_each(function()
        mock.flush_owned("all")
        ngx.shared.vn_config:flush_all()
        mock_config.kernel_ip_blocking.enabled = true
        mock_config.kernel_ip_blocking.mode = "observe"
    end)

    it("returns disabled when kernel blocking not enabled", function()
        mock_config.kernel_ip_blocking.enabled = false
        local r = reconcil.reconcile(ngx.time())
        assert.are.equal("disabled", r.skipped)
    end)

    it("observe mode does not install missing desired entries", function()
        mock_config.kernel_ip_blocking.mode = "observe"
        desired.set_desired("203.0.113.8", "ipv4", "scanner_drop", {}, 300)
        local r = reconcil.reconcile(ngx.time())
        assert.is_true(r.dry_run)
        assert.are.equal(1, #r.to_add)
        assert.are.equal(0, r.applied_add)
        local ok = mock.contains("scanner_drop", "ipv4", "203.0.113.8")
        assert.is_false(ok)
    end)

    it("lists each kernel set once instead of contains-scanning per desired entry", function()
        mock_config.kernel_ip_blocking.mode = "observe"
        for i = 1, 10 do
            desired.set_desired("203.0.113." .. i, "ipv4", "scanner_drop", {}, 300)
        end

        local original_list = mock.list
        local original_contains = mock.contains
        local list_calls = 0
        local contains_calls = 0
        mock.list = function(...)
            list_calls = list_calls + 1
            return original_list(...)
        end
        mock.contains = function(...)
            contains_calls = contains_calls + 1
            return original_contains(...)
        end

        local ok, err = pcall(function()
            local r = reconcil.reconcile(ngx.time())
            assert.are.equal(10, #r.to_add)
            assert.are.equal(6, list_calls)
            assert.are.equal(0, contains_calls)
        end)
        mock.list = original_list
        mock.contains = original_contains
        assert.is_true(ok, tostring(err))
    end)

    it("does not infer drift when a kernel set cannot be listed", function()
        mock_config.kernel_ip_blocking.mode = "observe"
        desired.set_desired("203.0.113.20", "ipv4", "scanner_drop", {}, 300)

        local original_list_strict = mock.list_strict
        mock.list_strict = function(set, family, cursor)
            if set == "scanner_drop" and family == "ipv4" then
                return nil, "helper_unavailable"
            end
            return mock.list(set, family, cursor)
        end

        local ok, err = pcall(function()
            local r = reconcil.reconcile(ngx.time())
            assert.are.equal(0, #r.to_add)
            assert.are.equal(0, #r.to_remove)
            assert.are.equal(1, r.failed)
        end)
        mock.list_strict = original_list_strict
        assert.is_true(ok, tostring(err))
    end)

    it("enforce mode applies missing desired entries", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        desired.set_desired("203.0.113.9", "ipv4", "scanner_drop",
            { reason = "test" }, 300, { policy = "scanner", source = "automatic" })
        local r = reconcil.reconcile(ngx.time())
        assert.is_false(r.dry_run)
        assert.are.equal(1, #r.to_add)
        assert.are.equal(1, r.applied_add)
        local ok = mock.contains("scanner_drop", "ipv4", "203.0.113.9")
        assert.is_true(ok)
        local e = sm.get_policy("203.0.113.9", "scanner")
        assert.truthy(e)
        assert.are.equal("installed", e.state)
    end)

    it("enforce mode removes orphan kernel entries not in desired", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        mock.add("scanner_drop", "ipv4", "198.51.100.1", 600)
        -- no desired entry for this IP
        local r = reconcil.reconcile(ngx.time())
        assert.are.equal(1, #r.to_remove)
        assert.are.equal(1, r.applied_remove)
        local ok = mock.contains("scanner_drop", "ipv4", "198.51.100.1")
        assert.is_false(ok)
    end)

    it("enforce backfills desired from installed state machine entries", function()
        mock_config.kernel_ip_blocking.mode = "enforce"
        -- installed in SM + kernel, but missing desired
        mock.add("scanner_drop", "ipv4", "198.51.100.2", 600)
        sm.upsert("198.51.100.2", "scanner", "installed", {}, {
            list = "scanner_drop",
            family = "ipv4",
            expires_at = ngx.time() + 600,
            source = "automatic",
        })
        local r = reconcil.reconcile(ngx.time())
        assert.are.equal(0, #r.to_remove)
        local d = desired.get_desired("198.51.100.2", "ipv4", "scanner_drop")
        assert.truthy(d)
        local ok = mock.contains("scanner_drop", "ipv4", "198.51.100.2")
        assert.is_true(ok)
    end)
end)

describe("Promotion writes desired_state", function()
    before_each(function()
        mock.flush_owned("all")
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
        mock_config.kernel_ip_blocking.enabled = true
        mock_config.kernel_ip_blocking.mode = "enforce"
        mock_config.kernel_ip_blocking.emergency_pause = false
        mock_config.kernel_ip_blocking.promotion_rate_limit = {
            limit = 1000, interval = 60, burst = 1000,
        }
        mock_config.kernel_ip_blocking.canary = { scanner_ttl = 60, cc_ttl = 30 }
        mock_config.kernel_ip_blocking.scanner = {
            enabled = true, min_hard_blocks = 3, max_ttl = 86400,
        }
        -- Pre-populate enforce bucket with tokens (Design §6.2)
        local tb_json = require("dkjson").encode({
            version = 1, tokens_microunits = 100000000,
            last_refill_ms = ngx.time() * 1000,
            limit = 1000, interval = 60, burst = 1000,
        })
        ngx.shared.vn_locks:set("kb:promotion_bucket:v1:enforce:state", tb_json, 0)
    end)

    it("enforce promotion installs and records desired entry", function()
        sm.upsert("203.0.113.10", "scanner", "observed", {}, {})
        promotion.process_candidates(ngx.time())
        local e = sm.get_policy("203.0.113.10", "scanner")
        assert.truthy(e)
        assert.are.equal("installed", e.state)
        local d = desired.get_desired("203.0.113.10", "ipv4", "scanner_drop")
        assert.truthy(d)
        assert.are.equal("scanner_drop", d.list)
        local ok = mock.contains("scanner_drop", "ipv4", "203.0.113.10")
        assert.is_true(ok)
    end)
end)

describe("index membership is never silently dropped", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
    end)

    it("desired set fails cleanly when the desired index lock cannot be acquired", function()
        -- Hold the index lock so index_add must exhaust its retry budget.
        ngx.shared.vn_locks:add("kb:desired_index_lock", 999, 10)
        local ok, err = desired.set_desired("198.51.100.9", "ipv4", "scanner_drop", {}, 600)
        assert.is_false(ok)
        assert.matches("failed to record", tostring(err))
        -- No orphaned entry: the state key must not exist without an index entry.
        assert.is_nil(ngx.shared.vn_config:get("kb:desired:ipv4:scanner_drop:198.51.100.9"))
        assert.is_nil(ngx.shared.vn_config:get("kb:desired_index"))
    end)

    it("state machine upsert fails cleanly when the candidate index lock cannot be acquired", function()
        ngx.shared.vn_locks:add("kb:candidate_index_lock", 999, 10)
        local ok, err = sm.upsert("198.51.100.10", "scanner", "candidate", {}, {})
        assert.is_false(ok)
        assert.matches("index lock unavailable", tostring(err))
        assert.is_nil(ngx.shared.vn_config:get("kb:candidate:198.51.100.10:scanner"))
        assert.is_nil(ngx.shared.vn_config:get("kb:candidate_index"))
    end)

    it("state machine upsert succeeds once the lock is released", function()
        ngx.shared.vn_locks:add("kb:candidate_index_lock", 999, 10)
        sm.upsert("198.51.100.11", "scanner", "candidate", {}, {})
        assert.is_nil(ngx.shared.vn_config:get("kb:candidate:198.51.100.11:scanner"))
        ngx.shared.vn_locks:delete("kb:candidate_index_lock")
        local ok, err = sm.upsert("198.51.100.11", "scanner", "candidate", {}, {})
        assert.is_true(ok, tostring(err))
        assert.truthy(ngx.shared.vn_config:get("kb:candidate:198.51.100.11:scanner"))
    end)
end)
