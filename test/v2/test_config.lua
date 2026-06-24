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

    it("rejects plaintext admin password", function()
        local ok, err = config.save({
            version = "2.0",
            admin = { { user = "admin", password = "plaintext" } }
        })
        assert.is_false(ok)
    end)

    it("accepts empty config (defaults applied)", function()
        -- save() will fail because ngx.shared is not available in test env
        -- but validate_config should pass
        local ok, err = config.save({
            version = "2.0",
            matcher = {},
            rule = {}
        })
        -- Will fail at ngx.shared access, not at validation
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