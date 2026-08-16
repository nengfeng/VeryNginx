-- -*- coding: utf-8 -*-
-- Whitelist publish path tests — ensures add/remove_whitelist go through
-- config.save() and do NOT mutate the read-only config store in-place.
--
-- Self-contained: sets up ngx + bit stubs in setup() so they persist
-- through busted's test execution model.

local function setup_ngx()
    if not _G.ngx then _G.ngx = {} end
    local ngx = _G.ngx
    function ngx.log() end
    ngx.ERR = 5
    ngx.WARN = 6
    ngx.time = function() return 1700000000 end
    ngx.md5 = function(s) return "h_" .. tostring(s):sub(1, 8) end
    ngx.crc32_short = function(s)
        local h = 0
        if s then for i = 1, #s do h = (h * 31 + string.byte(s, i)) % 2^32 end end
        return h
    end
    ngx.shared = setmetatable({}, {
        __index = function(_, name)
            ngx._stores = ngx._stores or {}
            ngx._counters = ngx._counters or {}
            if not ngx._stores[name] then
                ngx._stores[name] = {}
                ngx._counters[name] = {}
            end
            local st = ngx._stores[name]
            local cnt = ngx._counters[name]
            return {
                get = function(_, key) return st[key] end,
                set = function(_, key, val) st[key] = val; return true end,
                add = function(_, key, val)
                    if st[key] then return false end
                    st[key] = val; return true
                end,
                incr = function(_, key, delta, init)
                    local current = st[key]
                    if current == nil then
                        current = init or 0
                    else
                        current = tonumber(current) or 0
                    end
                    local new_val = current + delta
                    st[key] = new_val
                    cnt[key] = new_val
                    return new_val
                end,
                delete = function(_, key) st[key] = nil; cnt[key] = nil end,
                expire = function(_, key, ttl) end,
                get_keys = function() local k={}; for kk in pairs(st) do k[#k+1]=kk end return k end,
            }
        end,
    })
    package.preload["bit"] = function()
        local m = {}
        function m.band(a, b)
            local r, v = 0, 1
            while a > 0 or b > 0 do
                if a % 2 == 1 and b % 2 == 1 then r = r + v end
                a, b = math.floor(a / 2), math.floor(b / 2)
                v = v * 2
            end
            return r
        end
        return m
    end
end

setup_ngx()
local config = require "core.config"
local ir = require "core.ip_reputation"

local function fresh_ip_rep(whitelist)
    return {
        version = "2.0",
        admin = {},
        matcher = {},
        rule = {},
        ip_reputation = {
            enable = false,
            threshold = 25,
            flag_duration = 600,
            window_size = 300,
            slot_size = 60,
            min_requests = 3,
            pending_ttl = 600,
            whitelist = whitelist or {},
            signals = {},
        },
    }
end

describe("Whitelist publish path", function()
    setup(function()
        -- Re-establish ngx stubs in case busted cleared globals
        setup_ngx()
        -- Clear any save lock from previous test
        local s = _G.ngx.shared.vn_config
        if s then s:delete("config_save_lock") end
        -- Reset package cache so ip_reputation picks up fresh config
        package.loaded["core.ip_reputation"] = nil
    end)

    before_each(function()
        setup_ngx()
        local ok, err = config.save(fresh_ip_rep({}))
        assert.is_true(ok, "before_each save should succeed: " .. tostring(err))
    end)

    it("add_whitelist persists new entry via config.save()", function()
        ir.add_whitelist("192.168.1.0/24")
        local wl = config.ip_reputation.whitelist
        assert.are.equal(1, #wl)
        assert.are.equal("192.168.1.0/24", wl[1])
    end)

    it("add_whitelist does not duplicate existing entry", function()
        assert.is_true(config.save(fresh_ip_rep({ "10.0.0.0/8" })))
        ir.add_whitelist("10.0.0.0/8")
        local wl = config.ip_reputation.whitelist
        assert.are.equal(1, #wl)
    end)

    it("remove_whitelist removes existing entry", function()
        assert.is_true(config.save(fresh_ip_rep({ "10.0.0.0/8", "192.168.0.0/16" })))
        ir.remove_whitelist("10.0.0.0/8")
        local wl = config.ip_reputation.whitelist
        assert.are.equal(1, #wl)
        assert.are.equal("192.168.0.0/16", wl[1])
    end)

    it("is_whitelisted reflects changes after add_whitelist", function()
        local s = _G.ngx.shared.ip_reputation
        s:delete("ip_rep:wl_cache:203.0.113.1")
        package.loaded["core.ip_reputation"] = nil
        local ir2 = require "core.ip_reputation"
        assert.is_false(ir2.is_whitelisted("203.0.113.1"))
        ir2.add_whitelist("203.0.113.1")
        s:delete("ip_rep:wl_cache:203.0.113.1")
        assert.is_true(ir2.is_whitelisted("203.0.113.1"))
    end)
end)
