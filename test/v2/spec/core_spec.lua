-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : response resolver, session, and random unit tests

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

describe("Response resolver", function()
    local response = require "action.response"

    it("resolves inline table", function()
        local resp = response.resolve({ code = 200, content_type = "application/json", body = "{}" })
        assert.equals(200, resp.code)
        assert.equals("application/json", resp.content_type)
        assert.equals("{}", resp.body)
    end)

    it("returns default for nil", function()
        local resp = response.resolve(nil)
        assert.equals(403, resp.code)
    end)

    it("returns 500 for missing template", function()
        local resp = response.resolve("nonexistent_template")
        assert.equals(500, resp.code)
    end)
end)

describe("Random helper", function()
    local random = require "core.random"

    it("generates hex string of correct length", function()
        local hex = random.hex(16)
        assert.equals(32, #hex)
    end)
end)

describe("Session", function()
    local session = require "core.session"

    it("signs and verifies a token", function()
        local payload = { user = "admin", expire_at = 9999999999, nonce = "test" }
        local token = session.sign(payload, "secret123")
        assert.is_not_nil(token)

        local ok, result = session.verify(token, "secret123")
        assert.is_true(ok)
        assert.equals("admin", result.user)
    end)

    it("rejects expired token", function()
        local payload = { user = "admin", expire_at = 0, nonce = "test" }
        local token = session.sign(payload, "secret123")
        local ok, err = session.verify(token, "secret123")
        assert.is_false(ok)
    end)

    it("rejects invalid signature", function()
        local payload = { user = "admin", expire_at = 9999999999, nonce = "test" }
        local token = session.sign(payload, "secret123")
        local ok, err = session.verify(token, "wrong_secret")
        assert.is_false(ok)
    end)

    it("supports key rotation", function()
        local payload = { user = "admin", expire_at = 9999999999, nonce = "test" }
        local token = session.sign(payload, "new_secret")
        local secrets = { { secret = "old_secret" }, { secret = "new_secret" } }
        local ok, result = session.verify_with_rotation(token, secrets)
        assert.is_true(ok)
        assert.equals("admin", result.user)
    end)
end)

describe("constant_time_compare", function()
    local session = require "core.session"
    local ct = session._constant_time_compare

    it("returns true for equal strings", function()
        assert.is_true(ct("same", "same"))
    end)

    it("returns false for different strings", function()
        assert.is_false(ct("abc", "xyz"))
    end)

    it("returns false for non-string inputs", function()
        assert.is_false(ct(nil, "string"))
        assert.is_false(ct("string", 123))
        assert.is_false(ct({}, "table"))
    end)

    it("returns false for different length strings", function()
        assert.is_false(ct("short", "longer"))
    end)
end)