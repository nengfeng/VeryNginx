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
-- Every internal redirect re-enters this phase with a fresh context: the
-- index module (`/` -> `/index.php`), the try_files fallback, and the
-- proxy path's ngx.exec("@vn_proxy"). The redirect discards ngx.ctx and
-- re-runs the server-level `set` directives (which reset every $vn_*
-- request variable), so no marker kept in ngx.ctx or in a request
-- variable survives: the pipeline re-ran and the counting plugins
-- (frequency limit, traffic statistics, ip_reputation) charged the
-- client request once per pass. The marker lives in a per-worker table
-- keyed by the request id — see core/phase_guard.lua.
--
-- On the proxy path, the action decided in the first pass is restored
-- onto the fresh context so rule_engine.apply() below re-applies the
-- proxy target variables (which the redirect reset), and the exec is not
-- repeated.
local stored_action = phase_guard.stored_action()
if not ctx.has_decision(ctx) then
    if not phase_guard.marked() then
        plugin.execute_access(ctx)
        phase_guard.mark_run()
    end
    if stored_action then
        ctx.set_action(ctx, "proxy", stored_action)
    end
end

-- Apply the final decision
rule_engine.apply(ctx, "access")
