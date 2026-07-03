-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : log phase entry - execute plugin log hooks

local plugin = require "core.plugin"
local metrics = require "core.metrics"

local ctx = ngx.ctx.vn_ctx
if not ctx then
    return
end

-- Observe WAF end-to-end duration
if ctx.request and ctx.request.waf_start_time then
    metrics.observe("waf_request_duration", ngx.now() - ctx.request.waf_start_time, {})
end

plugin.execute_log(ctx)