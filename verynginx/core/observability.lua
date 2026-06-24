-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : observability - trace, plugin timing, health status

local _M = {}

function _M.init()
    -- Phase 6: register worker-level state collection timer
end

function _M.start_plugin_timer(ctx, plugin_name)
    if ctx and ctx.set_data then
        ctx.set_data(ctx, "timing:" .. plugin_name, ngx.now())
    end
end

function _M.finish_plugin_timer(ctx, plugin_name)
    if not ctx or not ctx.get_data then
        return
    end
    local start = ctx.get_data(ctx, "timing:" .. plugin_name)
    if start then
        local metrics = require "core.metrics"
        metrics.observe("plugin_duration_seconds", ngx.now() - start, { plugin = plugin_name })
    end
end

function _M.export_prometheus()
    local metrics = require "core.metrics"
    return metrics.export_prometheus()
end

return _M