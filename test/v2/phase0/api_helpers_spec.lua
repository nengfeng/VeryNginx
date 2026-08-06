-- -*- coding: utf-8 -*-
-- Tests for unified API input validation helper (api/helpers.lua).

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.req = { read_body = function() end, get_body_data = function() return nil end }

local helpers = require "api.helpers"

describe("api.helpers.is_valid_ip", function()

    it("accepts well-formed IPv4 addresses", function()
        assert.is_true(helpers.is_valid_ip("203.0.113.1"))
        assert.is_true(helpers.is_valid_ip("0.0.0.0"))
        assert.is_true(helpers.is_valid_ip("255.255.255.255"))
    end)

    it("rejects out-of-range or malformed IPv4", function()
        assert.is_false(helpers.is_valid_ip("999.1.1.1"))
        assert.is_false(helpers.is_valid_ip("1.2.3"))
        assert.is_false(helpers.is_valid_ip("1.2.3.4.5"))
        assert.is_false(helpers.is_valid_ip("1.2.3.4;drop"))
        assert.is_false(helpers.is_valid_ip("203.0.113.1:;drop"))
        assert.is_false(helpers.is_valid_ip("not-an-ip"))
    end)

    it("accepts well-formed IPv6 addresses", function()
        assert.is_true(helpers.is_valid_ip("::1"))
        assert.is_true(helpers.is_valid_ip("2001:db8::1"))
        assert.is_true(helpers.is_valid_ip("fe80::a1b2:c3d4"))
        assert.is_true(helpers.is_valid_ip("2001:0db8:0000:0000:0000:0000:0000:0001"))
    end)

    it("rejects malformed IPv6", function()
        assert.is_false(helpers.is_valid_ip(":::"))
        assert.is_false(helpers.is_valid_ip("1:2:3"))
        assert.is_false(helpers.is_valid_ip("2001:db8:::1"))
        assert.is_false(helpers.is_valid_ip("2001:gggg::1"))
        assert.is_false(helpers.is_valid_ip("2001:db8::1 "))
        assert.is_false(helpers.is_valid_ip("2001:db8:fffff::1"))
    end)

    it("rejects non-strings and empty input", function()
        assert.is_false(helpers.is_valid_ip(nil))
        assert.is_false(helpers.is_valid_ip(""))
        assert.is_false(helpers.is_valid_ip(12345))
        assert.is_false(helpers.is_valid_ip({}))
    end)
end)
