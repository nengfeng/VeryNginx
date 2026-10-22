-- -*- coding: utf-8 -*-
-- Phase re-entry guard (Phase 0)
--
-- The proxy path does an internal redirect (ngx.exec("@vn_proxy")) from the
-- access phase. The redirect re-runs the server-level rewrite phase, where
-- the `set` directives reset every $vn_* request variable to its default,
-- and it discards ngx.ctx: the second pass arrives with a fresh context and
-- re-runs the whole plugin pipeline, charging every counting plugin twice.
--
-- The marker lives in a per-worker table keyed by the request id
-- (core/phase_guard.lua): request variables cannot survive the redirect
-- (the re-run `set` directives reset them — measured in production), and
-- $request_id is stable across the redirect. These tests pin that
-- behaviour.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

local function setup_ngx(request_id)
    _G.ngx = {
        WARN = 6, ERR = 5, INFO = 4,
        time = function() return 1700000000 end,
        now = function() return 1700000000 end,
        md5 = function(s) return "x" end,
        ctx = {},
        var = { request_id = request_id },
    }
    function _G.ngx.log() end
end

local function stub_pipeline(calls)
    package.loaded["core.plugin"] = {
        execute_access = function(ctx) calls.access = calls.access + 1 end,
        execute_log = function(ctx) calls.log = calls.log + 1 end,
    }
    package.loaded["core.rule_engine"] = {
        apply = function(ctx, phase)
            calls.apply = calls.apply + 1
            calls.last_phase = phase
            -- the stub does not exec: record what the real engine would do
            if calls.on_apply then calls.on_apply(ctx, phase) end
        end
    }
end

describe("access phase re-entry guard", function()
    local calls, phase_guard

    before_each(function()
        calls = { access = 0, apply = 0, log = 0 }
        stub_pipeline(calls)
        -- a fresh module instance per test so the per-worker table does not
        -- leak between cases
        package.loaded["core.phase_guard"] = nil
        phase_guard = require "core.phase_guard"
        package.loaded["core.context"] = {
            new = function()
                return {
                    request = {}, data = {},
                    has_decision = function(ctx) return ctx.action_result ~= nil end,
                    set_action = function(ctx, t, d) ctx.action_result = { type = t, data = d } end,
                }
            end,
        }
        package.loaded["core.metrics"] = { observe = function() end }
    end)

    it("runs the pipeline on the first pass", function()
        setup_ngx("rid-a1")
        _G.ngx.ctx.vn_ctx = package.loaded["core.context"].new()
        dofile("verynginx/on_access.lua")
        assert.are.equal(1, calls.access)
        assert.are.equal(1, calls.apply)
    end)

    it("skips the plugins on the second pass but still applies the restored action", function()
        setup_ngx("rid-a2")
        local ctx_new = package.loaded["core.context"].new
        -- first pass: the pipeline runs and the proxy path execs
        _G.ngx.ctx.vn_ctx = ctx_new()
        dofile("verynginx/on_access.lua")
        assert.are.equal(1, calls.access)
        -- the real rule_engine stores the proxy action and execs before the
        -- redirect; simulate that here
        phase_guard.mark_executed({ host = "example.invalid" })
        -- second pass: the redirect re-entered the access phase with a
        -- fresh context
        _G.ngx.ctx = {}
        _G.ngx.ctx.vn_ctx = ctx_new()
        dofile("verynginx/on_access.lua")
        assert.are.equal(1, calls.access, "the plugins must not run a second time")
        assert.are.equal(2, calls.apply, "the decision is still applied (proxy target re-set)")
        assert.are.equal("example.invalid", _G.ngx.ctx.vn_ctx.action_result.data.host)
    end)

    it("drops the marker in the log phase so the table cannot grow unboundedly", function()
        setup_ngx("rid-a3")
        _G.ngx.ctx.vn_ctx = package.loaded["core.context"].new()
        dofile("verynginx/on_access.lua")
        phase_guard.mark_executed({ host = "example.invalid" })
        assert.is_true(phase_guard.executed())
        dofile("verynginx/on_log.lua")
        assert.is_falsy(phase_guard.executed())
    end)
end)

describe("rewrite phase re-entry guard", function()
    local actions, calls, phase_guard

    before_each(function()
        actions = { scheme = 0, redirect = 0, rewrite = 0 }
        calls = { access = 0, apply = 0, log = 0 }
        stub_pipeline(calls)
        package.loaded["core.phase_guard"] = nil
        phase_guard = require "core.phase_guard"
        package.loaded["core.config"] = { check_update = function() end }
        package.loaded["core.context"] = {
            new = function()
                return {
                    request = {}, data = {},
                    has_decision = function(ctx) return ctx.action_result ~= nil end,
                    set_action = function(ctx, t, d) ctx.action_result = { type = t, data = d } end,
                }
            end,
        }
        package.loaded["action.scheme_lock"] = { run = function() actions.scheme = actions.scheme + 1 end }
        package.loaded["action.redirect"] = { run = function() actions.redirect = actions.redirect + 1 end }
        package.loaded["action.rewrite"] = { run = function() actions.rewrite = actions.rewrite + 1 end }
    end)

    it("runs the rewrite-phase actions on the first pass", function()
        setup_ngx("rid-r1")
        dofile("verynginx/on_rewrite.lua")
        assert.are.equal(1, actions.scheme)
        assert.are.equal(1, actions.redirect)
        assert.are.equal(1, actions.rewrite)
    end)

    it("does not re-run the actions on the second pass, but still creates a context for the log phase", function()
        setup_ngx("rid-r2")
        dofile("verynginx/on_rewrite.lua")
        assert.are.equal(1, actions.scheme)
        -- simulate the exec the proxy path performed
        phase_guard.mark_executed({ host = "example.invalid" })
        -- second pass: the redirect re-entered the rewrite phase
        _G.ngx.ctx = {}
        dofile("verynginx/on_rewrite.lua")
        assert.are.equal(1, actions.scheme, "the scheme action must not run twice")
        assert.are.equal(1, actions.redirect)
        assert.are.equal(1, actions.rewrite, "a rewrite action must not rewrite the URI a second time")
        assert.is_truthy(_G.ngx.ctx.vn_ctx, "the log phase still needs its context")
    end)
end)
