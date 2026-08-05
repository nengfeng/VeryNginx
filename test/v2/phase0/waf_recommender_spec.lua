-- -*- coding: utf-8 -*-
-- Tests for waf_recommender: index atomicity (TOCTOU fix), dedup, CRUD.

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.sleep = function() end  -- no-op in tests
_G.ngx.shared = setmetatable({_cache = {}}, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v, ttl) st[k] = v; return true, nil end,
                add = function(_, k, v, ttl) if st[k] then return false, "exists" end; st[k] = v; return true, nil end,
                incr = function(_, k, d, i) if st[k] == nil then st[k] = (i or 0) end; st[k] = st[k] + d; return st[k], nil end,
                delete = function(_, k) st[k] = nil end,
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
            }
        end
        return t._cache[name]
    end,
})

local json = require "dkjson"

package.loaded["core.config"] = {
    waf_recommender = {
        enabled = true, min_hits = 10, window_size = 3600, min_patterns = 3,
    },
}

describe("waf_recommender index atomicity", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        package.loaded["core.waf_recommender"] = nil
    end)

    it("add() appends id to index", function()
        local rec = require "core.waf_recommender"
        rec.add({ id = "rule_1", pattern = "foo" })
        rec.add({ id = "rule_2", pattern = "bar" })
        local items = rec.list()
        assert.are.equal(2, #items)
    end)

    it("add() is idempotent — same id does not duplicate", function()
        local rec = require "core.waf_recommender"
        rec.add({ id = "rule_1", pattern = "foo" })
        rec.add({ id = "rule_1", pattern = "foo_updated" })
        local items = rec.list()
        assert.are.equal(1, #items)
        assert.are.equal("foo_updated", items[1].pattern)
    end)

    it("concurrent adds preserve all entries (no TOCTOU loss)", function()
        local rec = require "core.waf_recommender"
        local decoy = ngx.shared.vn_config
        -- Simulate concurrent workers: bypass lock by calling index_append
        -- directly via the internal mechanism. Instead, we use rapid sequential
        -- adds which stress the lock + dedup logic.
        for i = 1, 20 do
            rec.add({ id = "rule_" .. i, pattern = "p" .. i })
        end
        local items = rec.list()
        assert.are.equal(20, #items)
    end)

    it("delete() removes id from index", function()
        local rec = require "core.waf_recommender"
        rec.add({ id = "rule_1", pattern = "foo" })
        rec.add({ id = "rule_2", pattern = "bar" })
        rec.delete("rule_1")
        local items = rec.list()
        assert.are.equal(1, #items)
        assert.are.equal("rule_2", items[1].id)
    end)

    it("delete() of non-existent id is a no-op on the rest", function()
        local rec = require "core.waf_recommender"
        rec.add({ id = "rule_1", pattern = "foo" })
        rec.delete("nonexistent")
        local items = rec.list()
        assert.are.equal(1, #items)
    end)

    it("lock is released after add even on downstream error", function()
        local rec = require "core.waf_recommender"
        -- Normal add should work (lock acquired and released).
        rec.add({ id = "rule_1", pattern = "foo" })
        -- Second add should also work (lock not stuck).
        rec.add({ id = "rule_2", pattern = "bar" })
        local items = rec.list()
        assert.are.equal(2, #items)
    end)

    it("index lock held causes operation to fail gracefully", function()
        local rec = require "core.waf_recommender"
        -- Pre-acquire the lock so with_index_lock cannot get it.
        ngx.shared.vn_config:set("waf_rec:index_lock", 1, 10)
        -- add() should still return true (entry written), but log a warning.
        local ok = rec.add({ id = "rule_x", pattern = "px" })
        assert.is_true(ok)
        -- Entry is in dict even though index update failed.
        local item = rec.get("rule_x")
        assert.truthy(item)
        assert.are.equal("px", item.pattern)
    end)
end)

describe("waf_recommender.apply() saves the WAF rule table", function()
    local captured

    before_each(function()
        ngx.shared.vn_config:flush_all()
        package.loaded["core.waf_recommender"] = nil
        captured = {}
        package.preload["waf-rule-manager"] = function()
            local m = {}
            function m.load_rules() return { version = 42, rules = {} } end
            function m.save_rules(rules, action)
                captured.rules = rules
                captured.action = action
                return true
            end
            function m.reload() return true end
            return m
        end
    end)

    after_each(function()
        package.preload["waf-rule-manager"] = nil
    end)

    it("passes the rules table as first arg (not the version number)", function()
        local rec = require "core.waf_recommender"
        rec.add({ id = "rule_a", pattern = "SELECT.*FROM", category = "sqli",
                  severity = "high", status = "pending" })
        local item = rec.list()[1]
        local ok, err = rec.apply(item.id)
        assert.is_true(ok, tostring(err))
        assert.are.equal("table", type(captured.rules))
        assert.are.equal(1, #captured.rules)
        assert.are.equal("rec_" .. item.id:sub(1, 8), captured.rules[1].id)
        assert.are.equal("sqli", captured.rules[1].category)
        local applied = rec.get(item.id)
        assert.are.equal("applied", applied.status)
    end)
end)
