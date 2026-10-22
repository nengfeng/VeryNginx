-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : access phase entry - execute plugins with short-circuit, then apply

local plugin = require "core.plugin"
local rule_engine = require "core.rule_engine"
local phase_guard = require "core.phase_guard"

local ctx = ngx.ctx.vn_ctx
if not ctx then
    return
end

-- Re-entry guard: the proxy path's internal redirect re-enters this
-- phase, and the pipeline must run once per request. See
-- core/phase_guard.lua for why the marker cannot live in ngx.ctx.
if phase_guard.already_ran("vn_access_ran") then
    return
end

-- Skip if already decided in rewrite phase
if ctx.has_decision(ctx) then
    return
end

-- Execute all plugins (short-circuit on decision)
plugin.execute_access(ctx)

-- Apply the final decision
rule_engine.apply(ctx, "access")