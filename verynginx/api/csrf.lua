-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : CSRF token generation and verification

local _M = {}
local random = require "core.random"
local config = require "core.config"

--- Generate a CSRF token and store it in the session.
-- @param ctx table: request context
-- @return string: CSRF token
function _M.generate(ctx)
    local token = random.hex(32)
    if ctx and ctx.set_data then
        ctx.set_data(ctx, "csrf:token", token)
    end
    return token
end

--- Verify a CSRF token from request header against stored token.
-- @param ctx table: request context
-- @return boolean: true if valid
function _M.verify(ctx)
    if not config or not config.security or config.security.csrf == false then
        return true
    end

    local expected = ctx and ctx.get_data and ctx.get_data(ctx, "csrf:token")
    if not expected then
        return false
    end

    local provided = ngx.req.get_headers()["X-CSRF-Token"]
        or ngx.req.get_headers()["X-XSRF-Token"]
        or (ngx.req.get_post_args() or {})["csrf_token"]

    if not provided or provided ~= expected then
        return false
    end

    return true
end

return _M