-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : GeoIP controller - lookup, stats, config, updater

local _M = {}

local json = require "dkjson"

local function handle_geoip_lookup()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    local geoip_mod = require "core.geoip"
    local result = geoip_mod.lookup(ip)
    if not result then
        return json.encode({ ret = "success", data = nil, message = "IP not found in GeoIP database" })
    end
    return json.encode({ ret = "success", data = result })
end

local function handle_geoip_stats()
    local geoip_mod = require "core.geoip"
    local stats = geoip_mod.get_stats(ngx.shared.vn_config)
    return json.encode({ ret = "success", data = stats })
end

local function handle_geoip_config()
    local c = require "core.config"
    return json.encode({ ret = "success", data = c.geoip or {} })
end

local function handle_geoip_config_set()
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or raw == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end
    local ok, new_config = pcall(json.decode, raw)
    if not ok or type(new_config) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid JSON" })
    end
    local c = require "core.config"
    local cfg_data = c.report and json.decode(c.report()) or {}
    cfg_data.geoip = new_config
    local cfg_mod = require "core.config"
    local saved, save_err = cfg_mod.save(cfg_data)
    if not saved then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "config save failed: " .. tostring(save_err or "unknown") })
    end
    -- Reload GeoIP DB with new config (path may have changed)
    pcall(function()
        local geoip_mod = require "core.geoip"
        local new_path = (new_config.geodb_path ~= "" and new_config.geodb_path) or nil
        geoip_mod.init(new_path)
    end)
    return json.encode({ ret = "success", message = "GeoIP config updated" })
end

local function handle_geoip_status()
    local updater = require "core.geoip_updater"
    local status = updater.get_status()
    return json.encode({ ret = "success", data = status })
end

local function handle_geoip_update()
    local updater = require "core.geoip_updater"
    local ok, err, status = updater.check_update(true)
    if ok then
        return json.encode({ ret = "success", message = err })
    end
    ngx.status = status or 400
    return json.encode({ ret = "failed", message = tostring(err) })
end

function _M.register(api)
    api.register("GET",  "/geoip/lookup", handle_geoip_lookup,     true)
    api.register("GET",  "/geoip/stats",  handle_geoip_stats,      true)
    api.register("GET",  "/geoip/config", handle_geoip_config,     true)
    api.register("PUT",  "/geoip/config", handle_geoip_config_set, true)
    api.register("GET",  "/geoip/status", handle_geoip_status,     true)
    api.register("POST", "/geoip/update", handle_geoip_update,     true)
end

return _M
