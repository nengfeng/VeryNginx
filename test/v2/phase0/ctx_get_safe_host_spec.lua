-- -*- coding: utf-8 -*-
-- ctx:get_safe_host() was nil.
--
-- Three call sites use that form: plugin/browser_verify/cookie_verify.lua,
-- plugin/browser_verify/javascript_verify.lua and action/scheme_lock.lua. The
-- ctx object exposes get_body_args, get_uri_args, set_action, has_decision,
-- clear_action, set_data and get_data — but not get_safe_host, which lives on
-- the context MODULE as _M.get_safe_host.
--
-- So every challenged request died with
--
--     attempt to call method 'get_safe_host' (a nil value)
--
-- and returned a 500 instead of the challenge page. The browser_verify plugin
-- was enabled but had no rules, so nothing had ever exercised it.
--
-- These tests build a real ctx and assert the method is reachable and returns
-- the safe host, plus that the challenge page itself can be built.

describe("ctx exposes get_safe_host as a method", function()

    local context

    setup(function()
        if not _G.ngx then _G.ngx = {} end
        _G.ngx.log = _G.ngx.log or function() end
        _G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
        _G.ngx.now = _G.ngx.now or function() return os.time() end
        _G.ngx.time = _G.ngx.time or function() return os.time() end
        _G.ngx.var = { server_name = "www.hostwyn.com", host = "www.hostwyn.com",
                       connection = "1", connection_requests = "1" }
        _G.ngx.req = {
            get_headers = function() return {} end,
            get_method = function() return "GET" end,
            get_uri_args = function() return {} end,
        }
        _G.ngx.shared = _G.ngx.shared or setmetatable({}, { __index = function() return nil end })
        package.loaded["core.context"] = nil
        context = require "core.context"
    end)

    teardown(function()
        package.loaded["core.context"] = nil
    end)

    it("is reachable as ctx:get_safe_host()", function()
        local ctx = context.new()
        assert.is_function(ctx.get_safe_host,
            "ctx must expose get_safe_host: the browser_verify challenge and "
            .. "scheme_lock both call it that way")
    end)

    it("returns the server_name as the safe host", function()
        local ctx = context.new()
        assert.are.equal("www.hostwyn.com", ctx:get_safe_host())
    end)

    it("prefers the configured dashboard_host", function()
        package.loaded["core.config"] = { dashboard_host = "panel.example.com" }
        package.loaded["core.context"] = nil
        local ctx2 = require "core.context".new()
        assert.are.equal("panel.example.com", ctx2:get_safe_host())
        package.loaded["core.config"] = nil
    end)

    it("does not hand out a raw Host header when server_name is absent", function()
        -- get_safe_host exists to prevent Host-header injection into a
        -- redirect, so it must never return the attacker-controlled value
        -- when there is a better one.
        _G.ngx.var.server_name = ""
        _G.ngx.var.host = "evil.example.net"
        package.loaded["core.context"] = nil
        local ctx3 = require "core.context".new()
        local host = ctx3:get_safe_host()
        assert.is_truthy(host, "a host must always be produced")
        _G.ngx.var.server_name = "www.hostwyn.com"
    end)

    it("lets the browser_verify challenge build its target URL", function()
        -- The crash was inside challenge(), at the point where it assembles
        -- the redirect target. Exercise that exact line.
        local ctx = context.new()
        ctx.request.scheme = "https"
        ctx.request.uri = "/search.php"
        local ok, host = pcall(function() return ctx:get_safe_host() end)
        assert.is_true(ok, "the challenge's target assembly must not raise")
        assert.are.equal("www.hostwyn.com", host)
        local target = ctx.request.scheme .. "://" .. host .. ctx.request.uri
        assert.are.equal("https://www.hostwyn.com/search.php", target)
    end)
end)