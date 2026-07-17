-- -*- coding: utf-8 -*-
-- Tests for core/random.lua — PRNG seeding and fallback behavior.

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.now = function() return 1700000000.123456 end
_G.ngx.worker = { id = function() return 0 end }
_G.ngx.var = {}

describe("core/random", function()
    before_each(function()
        package.loaded["core.random"] = nil
    end)

    it("bytes() returns correct length", function()
        local random = require "core.random"
        local b = random.bytes(16)
        assert.are.equal(16, #b)
    end)

    it("hex() returns correct length (2 chars per byte)", function()
        local random = require "core.random"
        local h = random.hex(16)
        assert.are.equal(32, #h)
    end)

    it("hex() returns valid hex characters", function()
        local random = require "core.random"
        local h = random.hex(32)
        assert.truthy(h:match("^[0-9a-f]+$"))
    end)

    it("consecutive calls produce different values", function()
        local random = require "core.random"
        local b1 = random.bytes(16)
        local b2 = random.bytes(16)
        assert.are_not.equals(b1, b2)
    end)

    it("seed_prng is called on first fallback use", function()
        -- ngx.random_bytes is not available in test env, so fallback is used.
        -- Verify it doesn't crash and produces output.
        local random = require "core.random"
        local b = random.bytes(8)
        assert.are.equal(8, #b)
    end)
end)
