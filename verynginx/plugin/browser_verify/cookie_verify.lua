-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : browser verification via cookie challenge

local _M = {}

local config = require "core.config"

--- Compute verification signature for a given mark.
-- Uses session_secret instead of encrypt_seed for consistency with auth.
local function sign(ctx, mark)
    local ua = ngx.var.http_user_agent or ""
    local forwarded = ngx.var.http_x_forwarded_for or ""
    local seed = (config.security and config.security.session_secret) or "verynginx"
    return ngx.md5("VN" .. ctx.request.remote_addr .. forwarded .. ua .. mark .. seed)
end

--- Check if the request already has a valid verification cookie.
function _M.check(ctx)
    local cookie_sign = sign(ctx, "cookie")
    if ngx.var.http_cookie and ngx.var.http_cookie:find(cookie_sign, 1, true) then
        return true
    end
    return false
end

--- Issue a cookie challenge: set verification cookie and redirect.
function _M.challenge(ctx)
    local cookie_sign = sign(ctx, "cookie")
    local prefix = (config and config.cookie_prefix) or "verynginx"
    local cookie_str = prefix .. "_sign_cookie=" .. cookie_sign .. "; Path=/"
    ngx.header["Set-Cookie"] = cookie_str

    local target = ctx.request.scheme .. "://" .. ngx.var.http_host .. ctx.request.uri
    if ngx.var.query_string and ngx.var.query_string ~= "" then
        target = target .. "?" .. ngx.var.query_string
    end
    ngx.redirect(target, ngx.HTTP_MOVED_TEMPORARILY)
end

return _M