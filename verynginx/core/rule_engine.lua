-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : rule engine - execute rule chains with short-circuit, apply decisions

local _M = {}
local matcher = require "matcher.init"
local action_registry = require "action.init"
local response = require "action.response"
local static_file
do
    local ok, mod = pcall(require, "plugin.static_file.init")
    if ok then
        static_file = mod
    end
end

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

local function _no_backend_error()
    ngx.status = 502
    ngx.header["Content-Type"] = "text/plain"
    ngx.say("Bad Gateway: no backend configured for this request")
    return ngx.exit(502)
end

function _M.apply(ctx, phase)
    local action = ctx.action_result
    if not action then
        if phase == "rewrite" then
            return
        end
        -- No rule matched — clear proxy vars so the balancer skips
        ngx.var.vn_proxy_host = ""
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
    elseif action.type == RESULT.REWRITE then
        if phase == "rewrite" then
            ngx.req.set_uri(action.data.uri, false)
            ctx.clear_action(ctx)
            return
        end
        ngx.log(ngx.WARN, "rule_engine: rewrite action ignored — running in ", phase, " phase, not rewrite")
    elseif action.type == RESULT.PROXY then
        if not action.data or not action.data.host then
            ngx.log(ngx.ERR, "rule_engine: proxy action missing host data")
            return _no_backend_error()
        end
        ngx.ctx.vn_proxy_target = {
            host       = action.data.host,
            port       = action.data.port or "80",
            scheme     = action.data.scheme or "http",
            proxy_host = action.data.proxy_host or action.data.host,
            sni        = action.data.sni or action.data.host or "",
            websocket  = action.data.websocket == true,
        }
        return ngx.exec("@vn_proxy")
    elseif action.type == RESULT.STATIC then
        if not static_file or not static_file.serve then
            ngx.log(ngx.ERR, "rule_engine: static_file plugin not loaded")
            return _no_backend_error()
        end
        if not action.data or not action.data.root then
            ngx.log(ngx.ERR, "rule_engine: static action missing root")
            return _no_backend_error()
        end
        return static_file.serve(action.data.root, action.data.path, action.data.expires)
    elseif action.type == RESULT.ACCEPT then
        if not ngx.var.vn_proxy_host or ngx.var.vn_proxy_host == "" then
            return _no_backend_error()
        end
        return
    end
end

_M.RESULT = RESULT
return _M