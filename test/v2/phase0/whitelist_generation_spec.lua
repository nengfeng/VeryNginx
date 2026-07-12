-- -*- coding: utf-8 -*-
-- Tests for whitelist generation + generation-qualified cache (Phase 1)

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6
_G.ngx.time = function() return 1700000000 end
_G.ngx.shared = setmetatable({
    _cache = {},
}, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                _store = st,
                get = function(_, key) return st[key] end,
                set = function(_, key, val) st[key] = val; return true, nil end,
                add = function(_, key, val, ttl)
                    if st[key] then return false, "exists" end
                    st[key] = val
                    return true, nil
                end,
                incr = function(_, key, delta, init)
                    if st[key] == nil then
                        st[key] = (init or 0)
                    end
                    st[key] = st[key] + delta
                    return st[key], nil
                end,
                delete = function(_, key) st[key] = nil end,
                expire = function(_, key, ttl) end,
                flush_all = function()
                    for k in pairs(st) do st[k] = nil end
                end,
            }
        end
        return t._cache[name]
    end,
})

local wlg = require "core.kernel_blocking.whitelist_generation"

describe("Whitelist generation", function()
    before_each(function()
        ngx.shared.ip_reputation:flush_all()
    end)

    it("init_epoch creates a new epoch", function()
        ngx.shared.ip_reputation:flush_all()
        local epoch, seq = wlg.init_epoch()
        assert.truthy(epoch)
        assert.are.equal(1, seq)
    end)

    it("init_epoch returns existing epoch on second call", function()
        ngx.shared.ip_reputation:flush_all()
        local epoch1, seq1 = wlg.init_epoch()
        local epoch2, seq2 = wlg.init_epoch()
        assert.are.equal(epoch1, epoch2)
        assert.are.equal(1, seq2)
    end)

    it("bump_sequence increments", function()
        ngx.shared.ip_reputation:flush_all()
        local _, seq1 = wlg.init_epoch()
        local seq2 = wlg.bump_sequence()
        assert.are.equal(2, seq2)
        local seq3 = wlg.bump_sequence()
        assert.are.equal(3, seq3)
    end)

    it("cache_key includes epoch and sequence", function()
        ngx.shared.ip_reputation:flush_all()
        wlg.init_epoch()
        local key = wlg.cache_key("10.0.0.1")
        assert.truthy(key:find("^ip_rep:wl_cache:"))
        assert.truthy(key:find(":10%.0%.0%.1$"))
    end)

    it("cache_set then cache_get round-trip", function()
        ngx.shared.ip_reputation:flush_all()
        wlg.init_epoch()
        wlg.cache_set("192.168.1.1", true)
        assert.is_true(wlg.cache_get("192.168.1.1"))
    end)

    it("cache_get returns nil for miss", function()
        ngx.shared.ip_reputation:flush_all()
        wlg.init_epoch()
        assert.is_nil(wlg.cache_get("1.2.3.4"))
    end)

    it("cache invalidate removes entry", function()
        ngx.shared.ip_reputation:flush_all()
        wlg.init_epoch()
        wlg.cache_set("10.0.0.1", true)
        wlg.cache_invalidate("10.0.0.1")
        assert.is_nil(wlg.cache_get("10.0.0.1"))
    end)

    it("bump_sequence invalidates old generation caches", function()
        ngx.shared.ip_reputation:flush_all()
        wlg.init_epoch()
        wlg.cache_set("10.0.0.1", true)
        assert.is_true(wlg.cache_get("10.0.0.1"))
        local _, seq_before = wlg.get_generation()
        wlg.bump_sequence()
        local _, seq_after = wlg.get_generation()
        assert.are.equal(seq_before + 1, seq_after, "sequence should increment")
        assert.is_nil(wlg.cache_get("10.0.0.1"), "old gen cache should miss")
    end)
end)
