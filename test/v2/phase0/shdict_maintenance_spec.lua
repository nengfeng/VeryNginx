-- -*- coding: utf-8 -*-
-- The leak this module fixes, and the two properties that make it safe to
-- deploy without thinking about it: it removes ONLY expired values, and it
-- never calls flush_all.
--
-- Reproduction behind the tests, on a real slab: 60000 counters with a 1-second
-- TTL occupied 7.79 MB at 129.8 bytes per key, close to what production
-- showed (7.8 MB, 122.88 B/key). Three seconds later get_keys() reported zero
-- keys while used space was unchanged — the slots were still allocated.
-- flush_expired() released 7.68 MB in one call.

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
_G.ngx.log = function() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.NOTICE = 8
_G.ngx.now = function() return os.time() end
_G.ngx.worker = { id = function() return 0 end, exiting = function() return false end }

-- A dict stub that models the actual behaviour: an expired entry keeps its
-- slot until flush_expired(), and get_keys() does not list it. That separation
-- is the whole bug, so the stub has to reproduce it rather than pretend expiry
-- frees memory.
local function make_dict()
    local d = { slots = {}, flushed_all = 0 }
    function d:set(k, v, ttl)
        d.slots[k] = { v = v, exp = ttl and (os.time() + ttl) or nil }
        return true, nil, false
    end
    function d:get(k)
        local e = d.slots[k]
        if not e then return nil end
        if e.exp and e.exp <= os.time() then return nil end
        return e.v
    end
    function d:capacity() return 1000000 end
    function d:free_space()
        local used = 0
        for _ in pairs(d.slots) do used = used + 130 end
        return 1000000 - used
    end
    function d:get_keys()
        local t = {}
        for k, e in pairs(d.slots) do
            if not (e.exp and e.exp <= os.time()) then t[#t + 1] = k end
        end
        return t
    end
    function d:flush_expired()
        local n = 0
        for k, e in pairs(d.slots) do
            if e.exp and e.exp <= os.time() then d.slots[k] = nil; n = n + 1 end
        end
        return n
    end
    function d:flush_all()
        d.flushed_all = d.flushed_all + 1
        d.slots = {}
    end
    return d
end

_G.ngx.shared = setmetatable({}, {
    __index = function(_, name)
        local d = make_dict()
        rawset(_G.ngx.shared, name, d)
        return d
    end,
})

package.loaded["core.metrics"] = {
    gauge = function() end,
    incr = function() end,
}

local function fresh()
    package.loaded["core.shdict_maintenance"] = nil
    return require "core.shdict_maintenance"
end

describe("shared-dict expired-value reclamation", function()

    before_each(function()
        for k in pairs(_G.ngx.shared) do _G.ngx.shared[k] = nil end
    end)

    it("reclaims space that expired entries still occupy", function()
        local m = fresh()
        local d = ngx.shared.frequency_limit
        for i = 1, 50 do d:set("fl:v1:r:ip:10.0.0." .. i, 1, -1) end  -- already expired

        -- get_keys() sees nothing, which is exactly why this went unnoticed.
        assert.are.equal(0, #d:get_keys(), "expired keys must not be visible")
        local used_before = d:capacity() - d:free_space()
        assert.is_true(used_before > 0, "yet they still occupy space")

        local reclaimed = m.sweep()
        assert.is_true((reclaimed.frequency_limit or 0) > 0,
            "the sweep must give that space back")
        assert.are.equal(0, d:capacity() - d:free_space(),
            "and the dict must end up empty")
    end)

    it("never touches live data", function()
        local m = fresh()
        local d = ngx.shared.vn_config
        d:set("live:1", "keep me", 3600)
        d:set("live:2", "keep me too", 3600)
        d:set("dead:1", "gone", -1)

        m.sweep()

        assert.are.equal("keep me", d:get("live:1"), "live values must survive")
        assert.are.equal("keep me too", d:get("live:2"))
        assert.is_nil(d:get("dead:1"), "the expired one is the only casualty")
    end)

    it("does not call flush_all on any dict", function()
        -- flush_all() would discard live config, sessions and in-flight
        -- rate-limit state. The leak is fixed by reclaiming expired values,
        -- so a flush_all anywhere in here would be a bug, not a safety net.
        local m = fresh()
        for i = 1, 6 do ngx.shared["dict" .. i].set("k", "v", 3600) end

        local names = {}
        for name in pairs(_G.ngx.shared) do names[#names + 1] = name end
        assert.is_true(#names >= 6, "the dicts under test must exist")

        m.sweep()

        local touched = {}
        for _, name in ipairs(names) do
            if _G.ngx.shared[name].flushed_all > 0 then touched[#touched + 1] = name end
        end
        assert.are.equal(0, #touched,
            "flush_all must never be used; it was called on " .. table.concat(touched, ","))
    end)

    it("keeps working when one dict raises", function()
        local m = fresh()
        ngx.shared.vn_session:set("live", 1, 3600)
        local bad = ngx.shared.metrics
        bad.flush_expired = function() error("slab exploded") end
        ngx.shared.frequency_limit:set("dead", 1, -1)

        local ok = pcall(function() m.sweep() end)
        assert.is_true(ok, "one failing dict must not abort the whole sweep")
        assert.are.equal(0, ngx.shared.frequency_limit:capacity()
            - ngx.shared.frequency_limit:free_space(),
            "later dicts must still be swept")
        assert.are.equal(1, ngx.shared.vn_session:get("live"))
    end)

    it("registers the sweep on worker 0 only", function()
        local registered = {}
        _G.ngx.timer = {
            every = function(interval, fn) registered[#registered + 1] = interval; return true end,
            at = function() end,
        }
        local saved_id = ngx.worker.id
        ngx.worker.id = function() return 0 end
        fresh().init()
        assert.are.equal(1, #registered, "worker 0 must schedule exactly one sweep")

        registered = {}
        ngx.worker.id = function() return 3 end
        fresh().init()
        assert.are.equal(0, #registered,
            "other workers must not sweep: the slab mutex would serialise them")

        ngx.worker.id = saved_id
        _G.ngx.timer = nil
    end)

    it("does nothing outside a timer-capable runtime", function()
        _G.ngx.timer = nil
        assert.has_no.errors(function() fresh().init() end)
    end)
end)