-- -*- coding: utf-8 -*-
-- Tests for the password_hash redacted-sentinel guard in config.save().
-- Regression: Dashboard GET /config redacts password_hash to "(redacted)";
-- saving that back would overwrite the real hash and lock out all admins.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

local function ensure_ngx()
    if not _G.ngx then _G.ngx = {} end
    local ngx = _G.ngx
    function ngx.log() end
    ngx.WARN = 6; ngx.ERR = 5
    ngx.time = function() return 1700000000 end
    ngx.md5 = function(s) return "x" end
    ngx.random_bytes = function(n) return string.rep("R", n) end
    ngx.shared = setmetatable({}, {
        __index = function(_, name)
            ngx._stores = ngx._stores or {}
            ngx._expires = ngx._expires or {}
            if not ngx._stores[name] then ngx._stores[name] = {} end
            if not ngx._expires[name] then ngx._expires[name] = {} end
            local st = ngx._stores[name]
            local ex = ngx._expires[name]
            return {
                get = function(_, key)
                    if ex[key] and ngx.time() > ex[key] then
                        st[key] = nil; ex[key] = nil
                    end
                    return st[key]
                end,
                set = function(_, key, val, ttl)
                    st[key] = val
                    if ttl then ex[key] = ngx.time() + ttl end
                    return true
                end,
                add = function(_, key, val, ttl)
                    if ex[key] and ngx.time() > ex[key] then
                        st[key] = nil; ex[key] = nil
                    end
                    if st[key] then return false end
                    st[key] = val
                    if ttl then ex[key] = ngx.time() + ttl end
                    return true
                end,
                delete = function(_, key) st[key] = nil; ex[key] = nil end,
                expire = function(_, key, ttl)
                    if ttl then ex[key] = ngx.time() + ttl end
                end,
            }
        end,
    })
end
ensure_ngx()

local config = require "core.config"

describe("config.save password_hash redaction guard", function()
    before_each(function()
        ensure_ngx()
        -- seed a valid config so save() has a baseline
        config.save({ version = "2.0", admin = {}, matcher = {}, rule = {} })
    end)

    it("rejects save when password_hash is the redacted sentinel '(redacted)'", function()
        local cfg = {
            version = "2.0",
            admin = { { user = "admin", password_hash = "(redacted)", enable = true } },
            matcher = {},
            rule = {},
        }
        local ok, err = config.save(cfg)
        assert.is_false(ok, "save should reject redacted sentinel")
        assert.truthy(err and err:find("redacted"),
            "error should mention redacted: " .. tostring(err))
    end)

    it("accepts save when password_hash is a real p1$ hash", function()
        local cfg = {
            version = "2.0",
            admin = { { user = "admin", password_hash = "p1$12000$YWJj$ZGVm", enable = true } },
            matcher = {},
            rule = {},
        }
        local ok, err = config.save(cfg)
        assert.is_true(ok, "save should accept real hash: " .. tostring(err))
    end)
end)
