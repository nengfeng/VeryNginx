-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : log phase entry - execute plugin log hooks

local plugin = require "core.plugin"
local metrics = require "core.metrics"
local phase_guard = require "core.phase_guard"

-- Free this request's re-entry marker (see core/phase_guard.lua). It must
-- run even when the context is missing: the marker is keyed by the request
-- id, not by the context.
phase_guard.drop()

local ctx = ngx.ctx.vn_ctx
if not ctx then
    return
end

-- Observe WAF end-to-end duration
if ctx.request and ctx.request.waf_start_time then
    metrics.observe("waf_request_duration", ngx.now() - ctx.request.waf_start_time, {})
end

plugin.execute_log(ctx)