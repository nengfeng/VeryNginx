-- -*- coding: utf-8 -*-
-- Tests for candidate index full behavior (index_add_under_lock).
-- When the index reaches MAX_CANDIDATES, upsert must refuse (and roll back the
-- data entry) rather than silently creating an orphan that reconcile/list can
-- never discover. Guards the "never leave entry-without-index" rule (§12.2).

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
                add = function(_, k, v) if st[k] then return false, "exists" end
                    st[k] = v; return true, nil end,
                incr = function(_, k, d, i)
                    if st[k] == nil then st[k] = (i or 0) end
                    st[k] = st[k] + d; return st[k], nil end,
                delete = function(_, k) st[k] = nil end,
                expire = function() end,
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
            }
        end
        return t._cache[name]
    end,
})

local json = require "dkjson"

local function new_sm()
    package.loaded["core.kernel_blocking.state_machine"] = nil
    return require "core.kernel_blocking.state_machine"
end

describe("candidate index full", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
    end)

    -- Fill the index to exactly MAX_CANDIDATES by seeding the shared dict
    -- directly (single-threaded test; no lock contention).
    local function fill_index_to(n)
        local s = ngx.shared.vn_config
        local idx = {}
        for i = 1, n do
            idx[#idx + 1] = "10.0.0." .. tostring(i) .. ":scanner"
        end
        s:set("kb:candidate_index", json.encode(idx), 0)
    end

    it("upsert succeeds and indexes when below capacity", function()
        local sm = new_sm()
        fill_index_to(9999)
        local ok, err = sm.upsert("203.0.113.1", "scanner", "installed", {}, {})
        assert.is_true(ok, "upsert should succeed below capacity, err: " .. tostring(err))
        local idx = json.decode(ngx.shared.vn_config:get("kb:candidate_index"))
        assert.are.equal(10000, #idx, "index should have grown to 10000")
        assert.is_not_nil(ngx.shared.vn_config:get("kb:candidate:203.0.113.1:scanner"),
            "data entry must exist")
    end)

    it("upsert rolls back data entry when index is full (no orphan)", function()
        local sm = new_sm()
        fill_index_to(10000) -- exactly MAX_CANDIDATES
        local ok, err = sm.upsert("203.0.113.1", "scanner", "installed", {}, {})
        assert.is_false(ok, "upsert must fail when index is full")
        assert.truthy(err, "expected an error message")
        -- The data entry must NOT be left behind (rolled back).
        assert.is_nil(ngx.shared.vn_config:get("kb:candidate:203.0.113.1:scanner"),
            "data entry must be rolled back, not left as an orphan")
        -- Index must be unchanged.
        local idx = json.decode(ngx.shared.vn_config:get("kb:candidate_index"))
        assert.are.equal(10000, #idx, "index must not grow beyond capacity")
    end)

    it("upsert of an already-indexed key succeeds even when full (dedup)", function()
        local sm = new_sm()
        fill_index_to(10000)
        -- The last seeded key is 10.0.0.10000:scanner, already in the index.
        local ok, err = sm.upsert("10.0.0.10000", "scanner", "installed", {}, {})
        assert.is_true(ok, "dedup upsert of existing key must succeed, err: " .. tostring(err))
    end)
end)
