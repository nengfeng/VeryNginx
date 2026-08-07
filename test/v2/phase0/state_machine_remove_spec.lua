-- -*- coding: utf-8 -*-
-- Tests for state_machine.remove() index locking.
-- M2: remove()'s index read-modify-write must run under the index lock, or a
-- concurrent upsert (index_add_under_lock) can have its index append silently
-- overwritten by remove()'s stale index_write.

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
                    st[k] = st[k] + d
                    return st[k], nil end,
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

describe("state_machine.remove index locking", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
    end)

    -- remove() must delete both the per-(ip,policy) data key and the index
    -- entry, leaving a consistent state.
    it("remove deletes data key and index entry", function()
        local sm = new_sm()
        sm.upsert("203.0.113.1", "scanner", "installed", {}, {})
        assert.are.equal(1, sm.count and sm.count() or
            #json.decode(ngx.shared.vn_config:get("kb:candidate_index")))
        sm.remove("203.0.113.1", "scanner")
        local idx = json.decode(ngx.shared.vn_config:get("kb:candidate_index"))
        assert.are.equal(0, #idx)
        assert.is_nil(ngx.shared.vn_config:get("kb:candidate:203.0.113.1:scanner"))
    end)

    -- The core race (M2): remove()'s index read-modify-write must be atomic
    -- w.r.t. other index operations. We inject a concurrent UPSERT (add) — the
    -- dangerous production race is flush-auto removing entries while promotions
    -- add new ones. Without remove()'s index lock, remove()'s stale
    -- index_write clobbers the concurrent append, orphaning the new entry
    -- (its data key exists but is absent from the index -> invisible to
    -- reconcile forever).
    it("remove does not orphan a concurrent upsert's index entry", function()
        local sm = new_sm()
        -- Seed: ip1 (will be removed), ip2 (stays).
        sm.upsert("203.0.113.1", "scanner", "installed", {}, {})
        sm.upsert("203.0.113.2", "cc", "installed", {}, {})

        local s = ngx.shared.vn_config
        local INDEX_KEY = "kb:candidate_index"
        local injected_key = "kb:candidate:203.0.113.3:cc"

        -- Hook the index write: the moment remove() writes its filtered index,
        -- inject a concurrent upsert of ip3 (appends ip3 to the index under the
        -- lock). In the buggy version remove()'s stale write clobbers that
        -- append, leaving ip3 orphaned (data exists, not in index).
        local orig_set = s.set
        local injected = false
        s.set = function(_, k, v, ...)
            if k == INDEX_KEY and not injected then
                injected = true
                sm.upsert("203.0.113.3", "cc", "installed", {}, {})
            end
            return orig_set(_, k, v, ...)
        end

        sm.remove("203.0.113.1", "scanner")
        s.set = orig_set

        local idx = json.decode(s:get(INDEX_KEY))
        -- ip1 must be gone.
        for _, v in ipairs(idx) do
            assert.is_not_equal("203.0.113.1:scanner", v,
                "removed ip1 must not remain in index")
        end
        -- ip2 (keeper) must remain.
        local found_ip2 = false
        for _, v in ipairs(idx) do
            if v == "203.0.113.2:cc" then found_ip2 = true end
        end
        assert.is_true(found_ip2, "kept ip2 must remain in index")

        -- Consistency invariant: no data key may exist without an index entry
        -- (orphan). The buggy version leaves ip3's data in the shared dict
        -- while its index entry was clobbered by remove()'s stale write.
        local data_exists = s:get(injected_key) ~= nil
        local in_index = false
        for _, v in ipairs(idx) do
            if v == "203.0.113.3:cc" then in_index = true end
        end
        assert.is_false(data_exists and not in_index,
            "concurrent upsert must not be orphaned (data without index entry)")
    end)

    -- After remove(), the index lock must be released.
    it("remove releases the index lock", function()
        local sm = new_sm()
        sm.upsert("203.0.113.1", "scanner", "installed", {}, {})
        sm.remove("203.0.113.1", "scanner")
        assert.is_nil(ngx.shared.vn_locks:get("kb:candidate_index_lock"),
            "index lock must be released after remove")
    end)
end)
