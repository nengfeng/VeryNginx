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

-- Re-entry guard.
--
-- The proxy path does an internal redirect (ngx.exec("@vn_proxy")) from this
-- phase. The redirect re-runs the server-level rewrite phase, where the
-- `set` directives reset every $vn_* request variable to its default, and it
-- discards ngx.ctx, so this phase re-enters with a fresh context that has no
-- way to know the pipeline already ran. A marker kept in an nginx request
-- variable cannot survive (the re-run `set` directives reset it -- measured
-- in production), so the marker lives in a per-worker table keyed by the
-- request id: see core/phase_guard.lua.
--
-- On the second pass, the proxy action decided in the first pass is
-- restored onto the fresh context so rule_engine.apply() below re-applies
-- the proxy target variables (which the redirect reset). The plugins are
-- NOT re-run: the counting plugins (frequency limit, traffic statistics,
-- ip_reputation) would charge the request twice.
local stored_action = phase_guard.stored_action()
if not ctx.has_decision(ctx) then
    if stored_action then
        ctx.set_action(ctx, "proxy", stored_action)
    else
        plugin.execute_access(ctx)
    end
end

-- Apply the final decision
rule_engine.apply(ctx, "access")
