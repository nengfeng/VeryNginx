-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : CSRF token generation and verification

local _M = {}
local random = require "core.random"
local config = require "core.config"
local cookie = require "cookie"

--- Get the session token from the current request's cookie.
local function get_session_token()
    local cookie_obj = cookie:new()
    if not cookie_obj then
        return nil
    end
    local fields = cookie_obj:get_all()
    if not fields then
        return nil
    end
    local prefix = (config and config.cookie_prefix) or "verynginx"
    return fields[prefix .. "_session"]
end

--- Generate a CSRF token and store it keyed by the session token.
-- @param ctx table: request context
-- @return string: CSRF token
function _M.generate(ctx)
    local token = random.hex(32)
    local session = get_session_token()
    if session then
        local key = "csrf:" .. ngx.md5(session)
        local shared = ngx.shared.vn_locks
        if shared then
            shared:set(key, token, 3600)
        end
    end
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

    -- First try per-request ctx storage (same request generate+verify)
    local expected = ctx and ctx.get_data and ctx.get_data(ctx, "csrf:token")
    if not expected then
        local session = get_session_token()
        if session then
            local key = "csrf:" .. ngx.md5(session)
            local shared = ngx.shared.vn_locks
            if shared then
                expected = shared:get(key)
            end
        end
    end

    if not expected then
        return false
    end

    local provided = ngx.req.get_headers()["X-CSRF-Token"]
        or ngx.req.get_headers()["X-XSRF-Token"]

    if not provided then
        ngx.req.read_body()
        local post_args = ngx.req.get_post_args()
        provided = (post_args or {})["csrf_token"]
    end

    if not provided or provided ~= expected then
        return false
    end

    return true
end

return _M