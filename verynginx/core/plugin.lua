-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : plugin registry - register, sort, lifecycle hooks

local _M = {}

local config = require "core.config"
local metrics = require "core.metrics"

-- Sample rate (percentage) for plugin duration metrics. Avoids 2 shared
-- writes per plugin per request (14 writes total for 7 plugins) under load.
local METRICS_SAMPLE_PCT = 1

--- Plugin registry (sorted by priority)
_M.plugins = {}

--- Register a plugin.
-- @param plugin table: { name, priority, default_enable, critical, fail_code,
--                        on_init?, on_access?, on_log? }
function _M.register(plugin)
    table.insert(_M.plugins, plugin)
    table.sort(_M.plugins, function(a, b)
        local ap = (config.plugin and config.plugin[a.name] and config.plugin[a.name].priority) or a.priority
        local bp = (config.plugin and config.plugin[b.name] and config.plugin[b.name].priority) or b.priority
        return ap < bp
    end)
end

--- Check if a plugin is enabled (config overrides default).
function _M.is_enabled(plugin)
    local conf = config.plugin and config.plugin[plugin.name]
    if conf and conf.enable ~= nil then
        return conf.enable == true
    end
    return plugin.default_enable ~= false
end

--- Handle a plugin error. If critical, set a block action.
function _M.handle_error(plugin, ctx, phase, err)
    ngx.log(ngx.ERR, "plugin ", phase, " failed: ", plugin.name, " - ", err)
    if metrics and metrics.incr then
        metrics.incr("plugin_errors_total", 1, { plugin = plugin.name, phase = phase })
    end
    local conf = config.plugin and config.plugin[plugin.name]
    local critical = conf and conf.critical
    if critical == nil then
        critical = plugin.critical
    end
    if critical and ctx then
        ctx.set_action(ctx, "block", {
            code = plugin.fail_code or 503,
            response = "Service Unavailable"
        })
    end
end

--- Initialize all enabled plugins.
function _M.init_all()
    for _, plugin in ipairs(_M.plugins) do
        if _M.is_enabled(plugin) and plugin.on_init then
            local ok, err = pcall(plugin.on_init)
            if not ok then
                ngx.log(ngx.ERR, "plugin init failed: ", plugin.name, " - ", err)
            end
        end
    end
end

--- Terminal actions that end the request immediately after apply.
local TERMINAL_ACTIONS = { block = true, redirect = true, response = true, challenge = true }

--- Check if the current decision is terminal (stops further plugin execution).
function _M._is_terminal(ctx)
    local action = ctx.action_result
    if not action or not action.type then
        return false
    end
    return TERMINAL_ACTIONS[action.type] == true
end

--- Classify request once per access phase.
-- Sets ctx._is_admin to skip admin-only plugins (frequency_limit, browser_verify)
-- on backend requests, and skip backend plugins on admin requests.
local function classify_request(ctx)
    local base_uri = config.base_uri or "/verynginx"
    local uri = ctx.request.uri
    ctx._is_admin = uri:find(base_uri, 1, true) == 1
end

-- Plugins that only apply to backend (non-admin) traffic.
local BACKEND_ONLY = { frequency_limit = true, browser_verify = true }

--- Execute the access phase for all plugins.
-- Only terminal actions (block/redirect/response) short-circuit the loop;
-- non-terminal actions like accept, proxy, static allow downstream plugins to run.
function _M.execute_access(ctx)
    classify_request(ctx)
    for _, plugin in ipairs(_M.plugins) do
        if not _M.is_enabled(plugin) then
            goto continue
        end
        -- Skip backend-only plugins for admin requests
        if ctx._is_admin and BACKEND_ONLY[plugin.name] then
            goto continue
        end
        if ctx.has_decision(ctx) and _M._is_terminal(ctx) then
            break
        end
        if plugin.on_access then
            local t0 = ngx.now()
            local ok, err = pcall(plugin.on_access, ctx)
            if METRICS_SAMPLE_PCT >= 100 or math.random(100) <= METRICS_SAMPLE_PCT then
                metrics.observe("plugin_duration", ngx.now() - t0, { plugin = plugin.name })
            end
            if not ok then
                _M.handle_error(plugin, ctx, "access", err)
            end
        end
        ::continue::
    end
end

--- Execute the log phase for all enabled plugins.
function _M.execute_log(ctx)
    for _, plugin in ipairs(_M.plugins) do
        if _M.is_enabled(plugin) and plugin.on_log then
            local ok, err = pcall(plugin.on_log, ctx)
            if not ok then
                ngx.log(ngx.ERR, "plugin log failed: ", plugin.name, " - ", err)
            end
        end
    end
end

return _M