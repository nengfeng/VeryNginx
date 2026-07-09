-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : plugin + upstream health + top-paths controller

local _M = {}

local config = require "core.config"
local json = require "dkjson"

--- GET /plugins - list registered plugins with enable status
local function handle_list_plugins()
    local plugin_mod = require "core.plugin"
    local list = {}
    for _, p in ipairs(plugin_mod.plugins) do
        list[#list + 1] = {
            name = p.name,
            enable = plugin_mod.is_enabled(p),
            priority = p.priority,
            critical = p.critical or false,
            description = p.description or ""
        }
    end
    return json.encode({ ret = "success", data = list })
end

--- POST /plugins/:id/toggle - toggle a plugin's enabled state
local function handle_toggle_plugin()
    local name = ngx.ctx.waf_rule_id
    if not name or name == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "plugin name required" })
    end
    local config_mod = require "core.config"
    local plugins = config_mod.plugin
    if not plugins[name] then plugins[name] = {} end
    local entry = plugins[name]
    -- Determine current effective state from entry or plugin default
    local current = true
    if entry.enable ~= nil then
        current = entry.enable == true
    else
        local plugin_mod = require "core.plugin"
        for _, p in ipairs(plugin_mod.plugins) do
            if p.name == name then
                current = p.default_enable ~= false
                break
            end
        end
    end
    -- Build a plain save table from config.report(): avoids metatable /
    -- __pairs edge cases in some LuaJIT builds.
    local save_tbl = json.decode(config_mod.report())
    save_tbl.plugin = save_tbl.plugin or {}
    save_tbl.plugin[name] = save_tbl.plugin[name] or {}
    save_tbl.plugin[name].enable = not current
    local ok, err = config_mod.save(save_tbl)
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(err) })
    end
    -- Mirror into live config_data so subsequent reads see the new state
    entry.enable = save_tbl.plugin[name].enable
    return json.encode({ ret = "success", data = { name = name, enable = entry.enable } })
end

--- GET /upstreams/health - return runtime health status for all upstream nodes
local function handle_get_upstream_health()
    local upstreams_data = {}
    local health_shared = ngx.shared.healthcheck

    for name, upstream in pairs(config and config.backend_upstream or {}) do
        local nodes_status = {}
        for _, node in ipairs(upstream.nodes or {}) do
            local n = { host = node.host, port = node.port }
            if health_shared then
                local sk = "hc:" .. name .. ":" .. node.host .. ":" .. tostring(node.port)
                local state = health_shared:get(sk .. ":state")
                local failures = tonumber(health_shared:get(sk .. ":failures") or 0)
                local last_error = health_shared:get(sk .. ":last_error")
                n.healthy = (state ~= "unhealthy")
                n.failures = failures
                n.last_error = last_error
                local cb_key = "cb:" .. name .. ":" .. node.host .. ":" .. tostring(node.port)
                n.circuit_open = (health_shared:get(cb_key) == "open")
            else
                n.healthy = true
                n.failures = 0
                n.last_error = nil
                n.circuit_open = false
            end
            nodes_status[#nodes_status + 1] = n
        end
        upstreams_data[name] = nodes_status
    end

    return json.encode({ ret = "success", data = upstreams_data })
end

--- GET /stats/top-paths - top N request paths by count
local function handle_top_paths()
    local limit = tonumber(ngx.var.arg_limit) or 20
    if limit > 100 then limit = 100 end
    local stats_mod = require "core.statistics"
    local paths = stats_mod.get_top_paths(limit)
    return json.encode({ ret = "success", data = paths })
end

function _M.register(api)
    api.register("GET",  "/upstreams/health",   handle_get_upstream_health, true)
    api.register("GET",  "/plugins",            handle_list_plugins,        true)
    api.register("POST", "/plugins/:id/toggle",  handle_toggle_plugin,       true)
    api.register("GET",  "/stats/top-paths",     handle_top_paths,           true)
end

return _M
