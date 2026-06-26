-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : browser verification via JavaScript challenge

local _M = {}

local config = require "core.config"
local random = require "core.random"
local util = require "util"

local verify_html = nil

local function _get_seed()
    local s = config.security and config.security.session_secret
    if s and s ~= "" then
        return s
    end
    return random.hex(32)
end
local _fallback_seed = _get_seed()

--- Compute verification signature for JavaScript mark.
local function sign(ctx, mark)
    local ua = ngx.var.http_user_agent or ""
    local seed = (config.security and config.security.session_secret) or _fallback_seed
    return ngx.md5("VN" .. ctx.request.remote_addr .. ua .. mark .. seed)
end

--- Check if the request already passed the JavaScript challenge.
function _M.check(ctx)
    local js_sign = sign(ctx, "javascript")
    if ngx.var.http_cookie and ngx.var.http_cookie:find(js_sign, 1, true) then
        return true
    end
    return false
end

--- Issue a JavaScript challenge: serve verification page that sets cookie on JS execution.
function _M.challenge(ctx)
    if not verify_html then
        local path = require("core.config").resolve_path():match("(.+/)lua_script/")
            or "/opt/verynginx/verynginx/"
        path = path:gsub("lua_script/", "") .. "support/verify_javascript.html"
        local f = io.open(path, "r")
        if f then
            verify_html = f:read("*all")
            f:close()
        else
            verify_html = "<html><body><script>document.cookie='{{COOKIE}}';location='{{URI}}';</script></body></html>"
        end
    end

    local js_sign = sign(ctx, "javascript")
    local prefix = (config and config.cookie_prefix) or "verynginx"

    local target = ctx.request.scheme .. "://" .. ngx.var.http_host .. ctx.request.uri
    if ngx.var.query_string and ngx.var.query_string ~= "" then
        target = target .. "?" .. ngx.var.query_string
    end

    local html = verify_html
    html = html:gsub("INFOCOOKIE", js_sign)
    html = html:gsub("COOKIEPREFIX", prefix)
    html = util.string_replace(html, "INFOURI", target, 1)

    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-cache, no-store, must-revalidate"
    ngx.header["Pragma"] = "no-cache"
    ngx.header["Expires"] = "0"
    ngx.say(html)
    ngx.exit(200)
end

return _M