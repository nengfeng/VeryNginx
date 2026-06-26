-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : config unit tests (pure Lua, mock ngx.shared)

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

local config = require "core.config"

describe("Config validation", function()
    it("rejects invalid version", function()
        local ok, err = config.save({ version = "1.0" })
        assert.is_false(ok)
    end)

    it("rejects password stored as password_hash directly", function()
        local ok, err = config.save({
            version = "2.0",
            admin = { { user = "admin", password = "plaintext", password_hash = "plaintext" } }
        })
        assert.is_false(ok, "save should reject password == password_hash: " .. tostring(err))
    end)

    it("accepts empty config (defaults applied)", function()
        local ok, err = config.save({
            version = "2.0",
            matcher = {},
            rule = {}
        })
        assert.is_true(ok, "empty config with defaults should save: " .. tostring(err))
    end)
end)

describe("Config schema", function()
    it("has all required fields", function()
        assert.is_not_nil(config.schema)
        assert.is_not_nil(config.schema.fields)
        assert.is_not_nil(config.schema.fields.base_uri)
        assert.is_not_nil(config.schema.fields.matcher)
        assert.is_not_nil(config.schema.fields.rule)
        assert.is_not_nil(config.schema.fields.backend_upstream)
        assert.is_not_nil(config.schema.fields.security)
        assert.is_not_nil(config.schema.fields.body)
    end)

    it("has correct default for base_uri", function()
        assert.equals("/verynginx", config.schema.fields.base_uri.default)
    end)
end)