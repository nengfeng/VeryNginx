-- -*- coding: utf-8 -*-
-- Tests for the password_hash redacted-sentinel preservation in config.save().
-- Regression: Dashboard GET /config redacts password_hash to "(redacted)";
-- saving that back would overwrite the real hash and lock out all admins.
-- Fix: config.save() restores the real hash from config_data when the
-- incoming value is "(redacted)".

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

describe("config.save password_hash redaction preservation", function()
    before_each(function()
        ensure_ngx()
        -- Seed a valid config with a known admin hash.
        config.save({
            version = "2.0",
            admin = { { user = "admin", password_hash = "p1$12000$REAL$HASH", enable = true } },
            matcher = {},
            rule = {},
        })
    end)

    it("preserves real password_hash when incoming is '(redacted)'", function()
        local cfg = {
            version = "2.0",
            admin = { { user = "admin", password_hash = "(redacted)", enable = true } },
            matcher = {},
            rule = {},
        }
        local ok, err = config.save(cfg)
        assert.is_true(ok, "save should succeed with redacted sentinel: " .. tostring(err))
        -- After save, config_data should still have the real hash.
        local saved = config.admin and config.admin[1]
        assert.is_not_nil(saved, "admin entry should exist after save")
        assert.equals("p1$12000$REAL$HASH", saved.password_hash,
            "real hash must be preserved, not overwritten with (redacted)")
    end)

    it("accepts save when password_hash is a real p1$ hash", function()
        local cfg = {
            version = "2.0",
            admin = { { user = "admin", password_hash = "p1$12000$NEW$HASH", enable = true } },
            matcher = {},
            rule = {},
        }
        local ok, err = config.save(cfg)
        assert.is_true(ok, "save should accept real hash: " .. tostring(err))
        local saved = config.admin and config.admin[1]
        assert.equals("p1$12000$NEW$HASH", saved.password_hash)
    end)
end)
