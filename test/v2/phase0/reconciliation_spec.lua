-- -*- coding: utf-8 -*-
-- Tests for Phase 2: executor mock, desired state, reconciliation dry-run.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5
_G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
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

local mock = require "core.kernel_blocking.executor_mock"
local desired = require "core.kernel_blocking.desired_state"
local reconcil = require "core.kernel_blocking.reconciliation"
local contract = require "core.kernel_blocking.executor_contract"

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

    it("list returns matching entries", function()
        -- already tested above
    end)

    it("flush_owned removes all entries", function()
        mock.add("scanner_drop", "ipv4", "10.0.0.1", 0)
        mock.add("cc_drop", "ipv4", "10.0.0.2", 0)
        local r = mock.flush_owned("all")
        assert.are.equal(2, r.removed)
    end)

    it("reconcile computes add/update/remove", function()
        -- Start with one existing entry
        mock.add("scanner_drop", "ipv4", "10.0.0.1", 0)
        -- Reconcile with a different desired entry
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

describe("Desired state (dry-run)", function()
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
end)

describe("Reconciliation dry-run", function()
    before_each(function()
        mock.flush_owned("all")
        ngx.shared.vn_config:flush_all()
    end)

    it("returns disabled when kernel blocking not enabled", function()
        -- No config set; reconciliation should report disabled
        local r = reconcil.reconcile(ngx.time())
        assert.are.equal("disabled", r.skipped)
    end)
end)
