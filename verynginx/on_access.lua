-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : access phase entry - execute plugins with short-circuit, then apply

local plugin = require "core.plugin"
local rule_engine = require "core.rule_engine"

local ctx = ngx.ctx.vn_ctx
if not ctx then
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