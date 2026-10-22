-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : rule engine - execute rule chains with short-circuit, apply decisions

local _M = {}
local matcher = require "matcher.init"
local action_registry = require "action.init"
local response = require "action.response"
local phase_guard = require "core.phase_guard"
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
    CHALLENGE = "challenge",
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

--- Copy a response template's optional `headers` table onto the reply.
--- Content-Type is set by the caller afterwards, so a template may override
--- every other header (Retry-After on a 429, for example) without having to
--- re-declare the content type.
local function _apply_response_headers(resp)
    local headers = resp and resp.headers
    if type(headers) ~= "table" then
        return
    end
    for name, value in pairs(headers) do
        if type(name) == "string" and type(value) == "string" then
            ngx.header[name] = value
        end
    end
end

function _M.apply(ctx, phase)
    local action = ctx.action_result
    if not action then
        if phase == "rewrite" then
            return
        end
        -- No rule matched — clear proxy vars so the balancer skips.
        -- Wrap in pcall in case $vn_proxy_host is not defined in nginx.conf.
        pcall(function() ngx.var.vn_proxy_host = "" end)
        return
    end

    if action.type == RESULT.BLOCK then
        local resp = response.resolve(action.data.response) or {}
        ngx.status = action.data.code or resp.code or 403
        -- A block must never answer with a 2xx. Clients, access logs, the
        -- dashboard's block-rate counters and every CDN in front of us read a
        -- 200 as "served successfully" — and a cache in front may store and
        -- replay the body for legitimate users. The JS-challenge action is a
        -- separate type (RESULT.CHALLENGE below) and legitimately exits 200,
        -- so nothing legitimate depends on a 2xx here.
        if type(ngx.status) == "number" and ngx.status < 400 then
            ngx.log(ngx.WARN, "rule_engine: block action requested status ",
                    ngx.status, " — refusing, using 403 instead")
            ngx.status = 403
        end
        _apply_response_headers(resp)
        ngx.header["Content-Type"] = resp.content_type or "text/plain"
        ngx.say(resp.body or "Forbidden")
        return ngx.exit(ngx.status)
    elseif action.type == RESULT.REDIRECT then
        return ngx.redirect(action.data.url, action.data.code or 302)
    elseif action.type == RESULT.RESPONSE then
        local resp = response.resolve(action.data.response) or {}
        ngx.status = action.data.code or resp.code or 200
        _apply_response_headers(resp)
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
        -- Set nginx variables for @vn_proxy location (proxy_set_header +
        -- the balancer). Set on EVERY pass: the internal redirect re-runs
        -- the server-level `set` directives, which reset these to their
        -- defaults (see core/phase_guard.lua). Do NOT carry the target in
        -- ngx.ctx — the redirect re-runs the phases with a fresh ctx,
        -- losing it (peer would fall back to the upstream's 0.0.0.1 dummy
        -- server).
        pcall(function()
            ngx.var.vn_proxy_host   = action.data.host
            ngx.var.vn_proxy_port   = action.data.port or "80"
            ngx.var.vn_proxy_scheme = action.data.scheme or "http"
            ngx.var.vn_proxy_sni    = action.data.sni or action.data.host or ""
        end)
        -- Second pass after the exec: the target variables were just
        -- re-applied above, so fall through to the @vn_proxy content phase
        -- (which proxies) — do NOT exec again. $vn_in_exec cannot guard
        -- this: the redirect's re-run `set` directives reset it, so the
        -- marker lives in the per-worker table keyed by the request id.
        if phase_guard.executed() then
            return
        end
        local in_exec_ok, in_exec = pcall(function() return ngx.var.vn_in_exec end)
        if in_exec_ok and in_exec == "1" then
            return
        end
        pcall(function() ngx.var.vn_in_exec = "1" end)
        phase_guard.mark_executed(action.data)
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
    elseif action.type == RESULT.CHALLENGE then
        local verifier = action.data.cookie_verify
            or action.data.javascript_verify
            or require "plugin.browser_verify.javascript_verify"
        verifier.challenge(ctx)
        return ngx.exit(200)
    elseif action.type == RESULT.ACCEPT then
        local ok, host = pcall(function() return ngx.var.vn_proxy_host end)
        if not ok or not host or host == "" then
            return _no_backend_error()
        end
        return
    end
end

_M.RESULT = RESULT
return _M