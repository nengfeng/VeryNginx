-- -*- coding: utf-8 -*-
-- Tests for state machine + promotion observe evaluation (Phase 1)

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6
_G.ngx.time = function() return 1700000000 end
_G.ngx.shared = setmetatable({_cache={}}, {__index = function(t, name)
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
end})

package.preload["bit"] = function() return { band = function() return 0 end } end

local sm = require "core.kernel_blocking.state_machine"
local prom = require "core.kernel_blocking.promotion"

describe("State machine", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
    end)

    it("upsert and get candidate", function()
        sm.upsert_candidate("203.0.113.1", "scanner", "candidate",
            { block_hits = 5 })
        local c = sm.get_candidate("203.0.113.1")
        assert.truthy(c)
        assert.are.equal("203.0.113.1", c.ip)
        assert.are.equal("scanner", c.policy)
        assert.are.equal("candidate", c.state)
        assert.are.equal(5, c.evidence.block_hits)
    end)

    it("get_candidate returns nil for unknown", function()
        assert.is_nil(sm.get_candidate("1.2.3.4"))
    end)

    it("list candidates returns paginated results", function()
        for i = 1, 5 do
            sm.upsert_candidate("10.0.0." .. i, "scanner", "observed", {})
        end
        ngx.shared.vn_config:flush_all()  -- reset
        for i = 1, 5 do
            sm.upsert_candidate("10.0.0." .. i, "scanner", "observed", {})
        end
        local page = sm.list_candidates(0, 3)
        assert.are.equal(3, #page.entries)
        assert.truthy(page.next_cursor)
    end)

    it("count candidates", function()
        ngx.shared.vn_config:flush_all()
        sm.upsert_candidate("10.0.0.1", "scanner", "observed", {})
        sm.upsert_candidate("10.0.0.2", "scanner", "candidate", {})
        assert.are.equal(2, sm.count_candidates())
    end)
end)

describe("Promotion evaluate (observe-only)", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
    end)

    it("is a no-op when kernel blocking is not enabled", function()
        local ok, err = pcall(function()
            prom.process_candidates(ngx.time())
        end)
        assert.is_true(ok, "should not error when disabled: " .. tostring(err))
    end)
end)
