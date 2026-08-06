-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : IP reputation controller

local _M = {}

local json = require "dkjson"
local helpers = require "api.helpers"

local function handle_reputation_stats()
    local rep = require "core.ip_reputation"
    local stats = rep.get_stats()
    return json.encode({ ret = "success", data = stats })
end

local function handle_reputation_flagged()
    local rep = require "core.ip_reputation"
    local list = rep.list_flagged()
    return json.encode({ ret = "success", data = list })
end

local function handle_reputation_whitelist()
    local rep = require "core.ip_reputation"
    local list = rep.list_whitelist()
    return json.encode({ ret = "success", data = list })
end

local function handle_reputation_score()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    if not helpers.is_valid_ip(ip) then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid ip format" })
    end
    local rep = require "core.ip_reputation"
    return json.encode({
        ret = "success",
        data = {
            score = rep.get_score(ip),
            flagged = rep.is_flagged(ip),
            pending = rep.has_pending(ip),
            whitelisted = rep.is_whitelisted(ip),
        }
    })
end

local function handle_reputation_clear()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    if not helpers.is_valid_ip(ip) then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid ip format" })
    end
    local rep = require "core.ip_reputation"
    rep.clear_ip(ip)
    return json.encode({ ret = "success" })
end

local function handle_reputation_whitelist_add()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.req.read_body()
        local raw = ngx.req.get_body_data()
        if raw then
            local ok, parsed = pcall(json.decode, raw)
            if ok and parsed then ip = parsed.ip end
        end
    end
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    local rep = require "core.ip_reputation"
    if not rep.validate_whitelist_entry(ip) then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid ip or cidr" })
    end
    rep.add_whitelist(ip)
    return json.encode({ ret = "success" })
end

local function handle_reputation_whitelist_remove()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    local rep = require "core.ip_reputation"
    rep.remove_whitelist(ip)
    return json.encode({ ret = "success" })
end

local function handle_reputation_persist()
    local rep = require "core.ip_reputation"
    rep.persist()
    return json.encode({ ret = "success" })
end

function _M.register(api)
    api.register("GET",    "/reputation/stats",     handle_reputation_stats,            true)
    api.register("GET",    "/reputation/flagged",   handle_reputation_flagged,          true)
    api.register("GET",    "/reputation/whitelist", handle_reputation_whitelist,        true)
    api.register("GET",    "/reputation/score",     handle_reputation_score,            true)
    api.register("POST",   "/reputation/clear",     handle_reputation_clear,            true)
    api.register("POST",   "/reputation/whitelist", handle_reputation_whitelist_add,    true)
    api.register("DELETE", "/reputation/whitelist", handle_reputation_whitelist_remove, true)
    api.register("POST",   "/reputation/persist",   handle_reputation_persist,          true)
end

return _M
