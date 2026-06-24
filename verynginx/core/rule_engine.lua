-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : rule engine - execute rule chains with short-circuit, apply decisions

local _M = {}
local matcher = require "matcher.init"
local action_registry = require "action.init"
local response = require "action.response"
local static_file = pcall(require, "plugin.static_file.init") and require("plugin.static_file.init")

local RESULT = {
    PASS = "pass",
    ACCEPT = "accept",
    BLOCK = "block",
    REWRITE = "rewrite",
    REDIRECT = "redirect",
    RESPONSE = "response",
    PROXY = "proxy",
    STATIC = "static",
}

function _M.execute(rules, ctx)
    for _, rule in ipairs(rules or {}) do
        if not rule.enable then
            goto continue
        end
        local matched = matcher.test(rule.matcher, ctx)
        if matched then
            local handler = action_registry[rule.action]
            if handler then
                local result = handler(rule, ctx)
                if result and result.type ~= RESULT.PASS then
                    ctx.set_action(ctx, result.type, result.data)
                    return result
                end
            end
        end
        ::continue::
    end
    return { type = RESULT.PASS }
end

function _M.apply(ctx, phase)
    local action = ctx.action_result
    if not action then
        return
    end

    if action.type == RESULT.BLOCK then
        local resp = response.resolve(action.data.response)
        ngx.status = action.data.code or resp.code or 403
        ngx.header["Content-Type"] = resp.content_type or "text/plain"
        ngx.say(resp.body or "Forbidden")
        return ngx.exit(ngx.status)
    elseif action.type == RESULT.REDIRECT then
        return ngx.redirect(action.data.url, action.data.code or 302)
    elseif action.type == RESULT.RESPONSE then
        local resp = response.resolve(action.data.response)
        ngx.status = action.data.code or resp.code or 200
        ngx.header["Content-Type"] = resp.content_type or "text/plain"
        ngx.say(resp.body or "")
        return ngx.exit(ngx.status)
    elseif action.type == RESULT.REWRITE and phase == "rewrite" then
        ngx.req.set_uri(action.data.uri, false)
        ctx.clear_action(ctx)
        return
    elseif action.type == RESULT.PROXY then
        ngx.var.vn_proxy_scheme = action.data.scheme or "http"
        ngx.var.vn_proxy_host = action.data.host or ""
        ngx.var.vn_proxy_port = action.data.port or "80"
        ngx.var.vn_proxy_sni = action.data.sni or action.data.host or ""
    elseif action.type == RESULT.STATIC and static_file and static_file.serve then
        return static_file.serve(action.data.root, action.data.path, action.data.expires)
    elseif action.type == RESULT.ACCEPT then
        return
    end
end

_M.RESULT = RESULT
return _M