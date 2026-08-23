-- -*- coding: utf-8 -*-
-- Tests for whitelist entry format validation in config.validate_config.
-- The schema only checks items="string", so malformed entries like "999.1.1.1"
-- would otherwise pass and persist — silently defeating the is_whitelisted /
-- promote gate. validate_config must now reject them, mirroring the API layer's
-- validate_whitelist_entry (reputation.lua).

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

local function ensure_ngx()
    if not _G.ngx then _G.ngx = {} end
    local ngx = _G.ngx
    function ngx.log() end
    ngx.WARN = 6; ngx.ERR = 5
    ngx.time = function() return 1700000000 end
    ngx.md5 = function(s) return "x" end
    ngx.shared = setmetatable({}, {
        __index = function(_, name)
            ngx._stores = ngx._stores or {}
            if not ngx._stores[name] then ngx._stores[name] = {} end
            local st = ngx._stores[name]
            return {
                get = function(_, key) return st[key] end,
                set = function(_, key, val) st[key] = val; return true end,
                add = function(_, key, val)
                    if st[key] then return false end
                    st[key] = val; return true end,
                delete = function(_, key) st[key] = nil end,
                expire = function(_, key, ttl) end,
            }
        end,
    })
end
ensure_ngx()

-- ip_reputation.lua requires the `bit` module (LuaJIT/OpenResty only); stub it
-- so validate_whitelist_entry's CIDR check (bit.band) works under plain Lua.
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

local config = require "core.config"

local function with_whitelist(entries)
    return {
        version = "2.0",
        admin = {},
        matcher = {},
        matcher_id = {},
        rule = { frequency_limit = {} },
        frequency = { per_ip = { enabled = false } },
        cc = { enabled = false },
        kb_ip_blocking = {},
        kernel_ip_blocking = { enabled = false },
        statistics = { enable = false },
        summary = { enable = false },
        enable = true,
        enable_summary = false,
        protect_enable = false,
        allow_ip = {},
        allow_domain = {},
        body = {},
        proxy_pass = {},
        ssi = { enable = false },
        security = { session_secret = "x-secret-value-0123456789" },
        waf = { enable = false, rules = {} },
        request_filter = { enable = false, rules = {} },
        response_filter = { enable = false, rules = {} },
        frequency_limit = { enable = false, rules = {} },
        data_filter = { enable = false, rules = {} },
        ip_reputation = { whitelist = entries },
    }
end

describe("config whitelist entry validation", function()

    before_each(function() ensure_ngx() end)

    it("rejects out-of-range IPv4 octet 999.1.1.1", function()
        local ok, err = config.validate_config(with_whitelist({ "999.1.1.1" }))
        assert.is_false(ok, "999.1.1.1 must be rejected")
        assert.truthy(err and err:find("whitelist"), "error must mention whitelist: " .. tostring(err))
    end)

    it("rejects non-IP garbage string", function()
        local ok, err = config.validate_config(with_whitelist({ "not-an-ip" }))
        assert.is_false(ok, "non-IP string must be rejected")
    end)

    it("rejects host-bits-set CIDR 1.2.3.4/24", function()
        local ok, err = config.validate_config(with_whitelist({ "1.2.3.4/24" }))
        assert.is_false(ok, "1.2.3.4/24 (host bits set) must be rejected")
    end)

    it("rejects CIDR out of range /33", function()
        local ok, err = config.validate_config(with_whitelist({ "10.0.0.0/33" }))
        assert.is_false(ok, "/33 must be rejected")
    end)

    it("accepts valid single IP", function()
        local ok, err = config.validate_config(with_whitelist({ "10.0.0.1" }))
        assert.is_true(ok, "valid IP must be accepted: " .. tostring(err))
    end)

    it("accepts valid CIDR 10.0.0.0/8", function()
        local ok, err = config.validate_config(with_whitelist({ "10.0.0.0/8" }))
        assert.is_true(ok, "valid CIDR must be accepted: " .. tostring(err))
    end)

    it("accepts empty whitelist", function()
        local ok, err = config.validate_config(with_whitelist({}))
        assert.is_true(ok, "empty whitelist must be accepted: " .. tostring(err))
    end)

    it("rejects when one entry among several is invalid", function()
        local ok, err = config.validate_config(
            with_whitelist({ "10.0.0.1", "999.0.0.1", "192.168.1.0/24" }))
        assert.is_false(ok, "any invalid entry must fail the whole config")
        assert.truthy(err and err:find("999") or err:find("1]"),
            "error should point at the bad index: " .. tostring(err))
    end)
end)
