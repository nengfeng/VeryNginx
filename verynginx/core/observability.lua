-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : observability - trace, plugin timing, health status

local _M = {}

function _M.init()
    -- Register worker-level state collection timer (every 60 seconds)
    ngx.timer.every(60, function()
        _M._collect_worker_stats()
    end)
end

--- Collect worker-level statistics and expose as metrics.
function _M._collect_worker_stats()
    local metrics = require "core.metrics"

    -- Connection metrics
    metrics.gauge("nginx_connections_active", ngx.var.connections_active or 0)
    metrics.gauge("nginx_connections_reading", ngx.var.connections_reading or 0)
    metrics.gauge("nginx_connections_writing", ngx.var.connections_writing or 0)
    metrics.gauge("nginx_connections_waiting", ngx.var.connections_waiting or 0)

    -- Shared dict usage (approximate)
    local shared_dicts = { "vn_config", "vn_locks", "statistics", "metrics", "healthcheck", "dns_cache", "frequency_limit" }
    for _, name in ipairs(shared_dicts) do
        local shared = ngx.shared[name]
        if shared then
            local capacity = shared:capacity()
            local free_space = shared:free_space()
            local used = capacity - free_space
            if capacity > 0 then
                local pct = math.floor((used / capacity) * 100)
                metrics.gauge("shared_dict_usage_pct", pct, { dict = name })
            end
        end
    end
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