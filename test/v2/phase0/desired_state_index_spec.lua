-- -*- coding: utf-8 -*-
-- desired_state index compaction is triggered by count paths (not only list),
-- so dead index entries are pruned even when only count endpoints are called.

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

local json = require "dkjson"

-- Fresh module instance per test (reset _last_compact so the 300s throttle
-- does not suppress the compaction under test).
local function new_desired()
    package.loaded["core.kernel_blocking.desired_state"] = nil
    return require "core.kernel_blocking.desired_state"
end

describe("desired_state index compaction on count", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
    end)

    it("count_desired prunes dead entries even without a list_desired call", function()
        local desired = new_desired()
        desired.set_desired("203.0.113.1", "ipv4", "scanner_drop", {}, 600)
        desired.set_desired("203.0.113.2", "ipv4", "scanner_drop", {}, 600)
        assert.are.equal(2, desired.count_desired())

        -- Simulate entry expiry: the state key vanishes but stays in the index.
        ngx.shared.vn_config:delete("kb:desired:ipv4:scanner_drop:203.0.113.1")

        -- Advance past the 300s compact throttle so the next count actually
        -- compacts rather than short-circuiting on _last_compact.
        _G.ngx.time = function() return 1700000000 + 400 end

        -- count_desired must compact before counting, so the dead entry is gone.
        assert.are.equal(1, desired.count_desired())
        assert.are.equal(1, #json.decode(ngx.shared.vn_config:get("kb:desired_index")))
    end)

    it("clear_auto serializes with concurrent set_desired (no lost update / orphan)", function()
        local desired = new_desired()
        local s = ngx.shared.vn_config
        local locks = ngx.shared.vn_locks
        -- k1: scanner_drop (will be cleared), k2: manual_drop (kept)
        desired.set_desired("203.0.113.1", "ipv4", "scanner_drop", {}, 600)
        desired.set_desired("203.0.113.2", "ipv4", "manual_drop", {}, 600)

        -- Hook the shared dict delete to inject a concurrent set_desired
        -- mid-loop, simulating another worker adding an entry while
        -- clear_auto is running.
        local orig_del = s.delete
        local injected = false
        local injected_key = "kb:desired:ipv4:cc_drop:203.0.113.3"
        s.delete = function(_, k)
            if not injected then
                injected = true
                desired.set_desired("203.0.113.3", "ipv4", "cc_drop", {}, 600)
            end
            return orig_del(_, k)
        end

        local removed = desired.clear_auto()
        s.delete = orig_del

        assert.are.equal(1, removed, "exactly one scanner/cc entry removed")

        local idx = json.decode(s:get("kb:desired_index"))
        assert.are.equal(1, #idx, "only manual_drop remains in index")

        -- The concurrent cc_drop add must NOT be left as an orphan: either it
        -- is properly represented in the index, or fully rolled back (no data).
        local data_exists = s:get(injected_key) ~= nil
        local in_index = false
        for _, v in ipairs(idx) do
            if v == injected_key then in_index = true end
        end
        assert.is_false(data_exists and not in_index,
            "concurrent add must not be left orphaned (data without index)")

        -- The index lock must be free after clear_auto returns.
        assert.is_nil(locks:get("kb:desired_index_lock"),
            "index lock must be released after clear_auto")
    end)
end)