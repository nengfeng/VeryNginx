-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : matcher unit tests (pure Lua, no nginx dependency)

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

local matcher = require "matcher.init"

describe("Matcher registry", function()
    before_each(function()
        matcher.registry = {}
    end)

    it("registers and tests a simple matcher", function()
        matcher.register("test", function() return true end)
        local ctx = { request = {}, match_cache = {}, match_cache_size = 0, get_body_args = function() end, get_uri_args = function() return {} end, set_data = function() end, get_data = function() end }
        assert.is_true(matcher.test({ test = {} }, ctx))
    end)

    it("returns true for empty matcher", function()
        local ctx = { request = {}, match_cache = {}, match_cache_size = 0 }
        assert.is_true(matcher.test({}, ctx))
        assert.is_true(matcher.test(nil, ctx))
    end)

    it("returns false for unknown condition type", function()
        local ctx = { request = {}, match_cache = {}, match_cache_size = 0 }
        assert.is_false(matcher.test({ unknown_type = {} }, ctx))
    end)
end)

describe("URI matcher", function()
    local uri_matcher = require "matcher.uri"

    it("matches exact URI", function()
        local ctx = { request = { uri = "/admin" }, match_cache = {}, match_cache_size = 0 }
        matcher.register("URI", uri_matcher.test)
        assert.is_true(matcher.test({ URI = { operator = "=", value = "/admin" } }, ctx))
        assert.is_false(matcher.test({ URI = { operator = "=", value = "/other" } }, ctx))
    end)

    it("matches regex URI", function()
        local ctx = { request = { uri = "/user/123" }, match_cache = {}, match_cache_size = 0 }
        matcher.register("URI", uri_matcher.test)
        assert.is_true(matcher.test({ URI = { operator = "≈", value = "/user/%d+" } }, ctx))
        assert.is_false(matcher.test({ URI = { operator = "≈", value = "^/admin" } }, ctx))
    end)
end)

describe("IP matcher", function()
    local ip_matcher = require "matcher.ip"

    it("matches exact IP", function()
        local ctx = { request = { remote_addr = "192.168.1.1" }, match_cache = {}, match_cache_size = 0 }
        matcher.register("IP", ip_matcher.test)
        assert.is_true(matcher.test({ IP = { operator = "=", value = "192.168.1.1" } }, ctx))
        assert.is_false(matcher.test({ IP = { operator = "=", value = "10.0.0.1" } }, ctx))
    end)
end)

describe("UserAgent matcher", function()
    local ua_matcher = require "matcher.ua"

    it("matches user agent pattern", function()
        local ctx = { request = { user_agent = "Mozilla/5.0 Chrome/91" }, match_cache = {}, match_cache_size = 0 }
        matcher.register("UserAgent", ua_matcher.test)
        assert.is_true(matcher.test({ UserAgent = { operator = "≈", value = "Chrome" } }, ctx))
        assert.is_false(matcher.test({ UserAgent = { operator = "≈", value = "curl" } }, ctx))
    end)
end)

describe("Host matcher", function()
    local host_matcher = require "matcher.host"

    it("matches host", function()
        local ctx = { request = { host = "example.com" }, match_cache = {}, match_cache_size = 0 }
        matcher.register("Host", host_matcher.test)
        assert.is_true(matcher.test({ Host = { operator = "=", value = "example.com" } }, ctx))
    end)
end)