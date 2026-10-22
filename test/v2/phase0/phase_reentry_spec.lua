-- -*- coding: utf-8 -*-
-- Phase re-entry guard (Phase 0)
--
-- Every internal redirect re-enters the rewrite and access phases with a
-- fresh context: the index module (`/` -> `/index.php`), the try_files
-- fallback, and the proxy path's ngx.exec("@vn_proxy"). The redirect
-- discards ngx.ctx and re-runs the server-level `set` directives (which
-- reset every $vn_* request variable), so no marker kept in ngx.ctx or a
-- request variable survives: the pipeline re-ran and the counting plugins
-- charged the client request once per pass.
--
-- The marker lives in a per-worker table keyed by the request id
-- (core/phase_guard.lua): $request_id is stable across the redirect and
-- untouched by the `set` directives. These tests pin that behaviour.

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

local function new_ctx()
    return {
        request = {}, data = {},
        has_decision = function(ctx) return ctx.action_result ~= nil end,
        set_action = function(ctx, t, d) ctx.action_result = { type = t, data = d } end,
    }
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
        end,
    }
end

local function stub_actions(counts)
    package.loaded["core.config"] = { check_update = function() end }
    package.loaded["action.scheme_lock"] = { run = function() counts.scheme = counts.scheme + 1 end }
    package.loaded["action.redirect"] = { run = function() counts.redirect = counts.redirect + 1 end }
    package.loaded["action.rewrite"] = { run = function() counts.rewrite = counts.rewrite + 1 end }
end

local function fresh_phase_guard()
    package.loaded["core.phase_guard"] = nil
    return require "core.phase_guard"
end

describe("access phase re-entry guard", function()
    local calls, phase_guard

    before_each(function()
        calls = { access = 0, apply = 0, log = 0 }
        stub_pipeline(calls)
        phase_guard = fresh_phase_guard()
        package.loaded["core.context"] = { new = new_ctx }
        package.loaded["core.metrics"] = { observe = function() end }
    end)

    it("runs the pipeline once on the first pass and marks the request", function()
        setup_ngx("rid-a1")
        _G.ngx.ctx.vn_ctx = new_ctx()
        dofile("verynginx/on_access.lua")
        assert.are.equal(1, calls.access)
        assert.are.equal(1, calls.apply)
        assert.is_true(phase_guard.marked())
    end)

    it("skips the pipeline on the second pass of an internal redirect (index module)", function()
        -- first pass: GET / -> the index module will internally redirect
        -- to /index.php
        setup_ngx("rid-a2")
        _G.ngx.ctx.vn_ctx = new_ctx()
        dofile("verynginx/on_access.lua")
        assert.are.equal(1, calls.access)
        -- second pass: the redirect re-entered the access phase with a
        -- fresh context; the counting plugins must not run again
        _G.ngx.ctx = {}
        _G.ngx.ctx.vn_ctx = new_ctx()
        dofile("verynginx/on_access.lua")
        assert.are.equal(1, calls.access, "the plugins must not charge the request twice")
        assert.are.equal(2, calls.apply, "the decision is still applied on every pass")
    end)

    it("restores the proxy action on the second pass and does not re-run the plugins", function()
        setup_ngx("rid-a3")
        _G.ngx.ctx.vn_ctx = new_ctx()
        dofile("verynginx/on_access.lua")
        assert.are.equal(1, calls.access)
        -- the real rule_engine stores the proxy action and execs just
        -- before the redirect; simulate that
        phase_guard.mark_executed({ host = "example.invalid" })
        -- second pass: fresh context after the redirect
        _G.ngx.ctx = {}
        local ctx2 = new_ctx()
        _G.ngx.ctx.vn_ctx = ctx2
        dofile("verynginx/on_access.lua")
        assert.are.equal(1, calls.access, "the plugins must not run a second time")
        assert.are.equal(2, calls.apply, "rule_engine.apply re-applies the restored action")
        assert.are.equal("example.invalid", ctx2.action_result.data.host)
        assert.are.equal("proxy", ctx2.action_result.type)
    end)

    it("drops the marker in the log phase so the table cannot grow unboundedly", function()
        setup_ngx("rid-a4")
        _G.ngx.ctx.vn_ctx = new_ctx()
        dofile("verynginx/on_access.lua")
        assert.is_true(phase_guard.marked())
        dofile("verynginx/on_log.lua")
        assert.is_falsy(phase_guard.marked())
    end)
end)

describe("rewrite phase re-entry guard", function()
    local counts, calls, phase_guard

    before_each(function()
        counts = { scheme = 0, redirect = 0, rewrite = 0 }
        calls = { access = 0, apply = 0, log = 0 }
        stub_pipeline(calls)
        phase_guard = fresh_phase_guard()
        stub_actions(counts)
        package.loaded["core.context"] = { new = new_ctx }
    end)

    it("runs the rewrite-phase actions on the first pass", function()
        setup_ngx("rid-r1")
        dofile("verynginx/on_rewrite.lua")
        assert.are.equal(1, counts.scheme)
        assert.are.equal(1, counts.redirect)
        assert.are.equal(1, counts.rewrite)
    end)

    it("does not re-run the actions on the second pass, but still creates a context for the log phase", function()
        setup_ngx("rid-r2")
        dofile("verynginx/on_rewrite.lua")
        assert.are.equal(1, counts.scheme)
        -- the first pass's pipeline ran (on_access would have marked the
        -- request); simulate that
        phase_guard.mark_run()
        -- second pass: the redirect re-entered the rewrite phase
        _G.ngx.ctx = {}
        dofile("verynginx/on_rewrite.lua")
        assert.are.equal(1, counts.scheme, "the scheme action must not run twice")
        assert.are.equal(1, counts.redirect)
        assert.are.equal(1, counts.rewrite, "a rewrite action must not rewrite the URI a second time")
        assert.is_truthy(_G.ngx.ctx.vn_ctx, "the log phase still needs its context")
    end)
end)
