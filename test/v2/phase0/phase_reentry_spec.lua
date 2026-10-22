-- -*- coding: utf-8 -*-
-- Phase re-entry guards (Phase 0)
--
-- The proxy path does an internal redirect (ngx.exec("@vn_proxy")) from the
-- access phase, which re-enters the rewrite and access phases. ngx.exec()
-- discards ngx.ctx, so a marker kept in ngx.ctx cannot see the second pass:
-- the plugin pipeline ran twice and every request was counted twice (the
-- rate limiter, ip_reputation's request counter and the traffic statistics).
--
-- The markers live in nginx request variables, which DO survive the internal
-- redirect. These tests pin that behaviour.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

local function setup_ngx()
    if not _G.ngx then _G.ngx = {} end
    local ngx = _G.ngx
    function ngx.log() end
    ngx.WARN = 6; ngx.ERR = 5; ngx.INFO = 4
    ngx.time = function() return 1700000000 end
    ngx.now = function() return 1700000000 end
    ngx.md5 = function(s) return "x" end
    ngx.ctx = {}
    ngx.var = {}
    return ngx
end

local function stub_pipeline(calls)
    package.loaded["core.plugin"] = {
        execute_access = function(ctx) calls.access = calls.access + 1 end,
        execute_log = function(ctx) calls.log = calls.log + 1 end,
    }
    package.loaded["core.rule_engine"] = {
        apply = function(ctx, phase) calls.apply = (calls.apply or 0) + 1; calls.phase = phase end,
    }
end

describe("access phase re-entry guard", function()
    local calls

    before_each(function()
        setup_ngx()
        calls = { access = 0, log = 0, apply = 0 }
        stub_pipeline(calls)
    end)

    it("runs the plugin pipeline on the first pass", function()
        _G.ngx.ctx.vn_ctx = { has_decision = function() return false end }
        dofile("verynginx/on_access.lua")
        assert.are.equal(1, calls.access)
        assert.are.equal(1, calls.apply)
    end)

    it("does not run the pipeline again after the internal redirect", function()
        -- ngx.exec() discarded ngx.ctx, so the second pass arrives with a
        -- fresh context -- but the request variable still says the pipeline
        -- already ran.
        _G.ngx.ctx.vn_ctx = { has_decision = function() return false end }
        _G.ngx.var.vn_access_ran = "1"
        dofile("verynginx/on_access.lua")
        assert.are.equal(0, calls.access)
        assert.are.equal(0, calls.apply)
    end)

    it("marks the request so the second pass is skipped", function()
        _G.ngx.ctx.vn_ctx = { has_decision = function() return false end }
        dofile("verynginx/on_access.lua")
        assert.are.equal("1", _G.ngx.var.vn_access_ran)
    end)
end)

describe("rewrite phase re-entry guard", function()
    local calls, actions

    before_each(function()
        setup_ngx()
        calls = { access = 0, log = 0, apply = 0 }
        actions = { scheme = 0, redirect = 0, rewrite = 0 }
        stub_pipeline(calls)
        package.loaded["core.config"] = { check_update = function() end }
        package.loaded["core.context"] = {
            new = function() return { request = {}, data = {} } end,
        }
        package.loaded["action.scheme_lock"] = { run = function() actions.scheme = actions.scheme + 1 end }
        package.loaded["action.redirect"] = { run = function() actions.redirect = actions.redirect + 1 end }
        package.loaded["action.rewrite"] = { run = function() actions.rewrite = actions.rewrite + 1 end }
    end)

    it("runs the rewrite-phase actions on the first pass", function()
        dofile("verynginx/on_rewrite.lua")
        assert.are.equal(1, actions.scheme)
        assert.are.equal(1, actions.redirect)
        assert.are.equal(1, actions.rewrite)
    end)

    it("does not run them again after the internal redirect", function()
        -- The URI must not be rewritten a second time.
        _G.ngx.var.vn_rewrite_ran = "1"
        dofile("verynginx/on_rewrite.lua")
        assert.are.equal(0, actions.scheme)
        assert.are.equal(0, actions.redirect)
        assert.are.equal(0, actions.rewrite)
    end)

    it("still creates a context on the second pass for the log phase", function()
        -- ngx.exec() discarded the first pass's context, and the log phase
        -- needs one (it reports the WAF latency and the request statistics).
        _G.ngx.var.vn_rewrite_ran = "1"
        dofile("verynginx/on_rewrite.lua")
        assert.is_truthy(_G.ngx.ctx.vn_ctx)
    end)
end)
