-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : auth controller - login / logout

local _M = {}

local config = require "core.config"
local auth = require "api.auth"
local json = require "dkjson"
local helpers = require "api.helpers"
local audit = require "core.audit"

--- POST /login - authenticate and return session token
local function handle_login()
    local args = helpers.get_request_args()
    local user = args.user
    local password = args.password
    if not user or not password then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "user and password required" })
    end

    local strategy = auth.strategies[config.auth_strategy or "session"]
    if not strategy then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "auth strategy not available" })
    end

    local ok, result = strategy.login(user, password)
    if not ok then
        ngx.status = 401
        audit.log("login_failed", result, user)
        return json.encode({ ret = "failed", message = result })
    end

    auth.set_session_cookie(result)
    ngx.status = 200
    audit.log("login_success", "", user)
    return json.encode({ ret = "success", token = result })
end

--- POST /logout - revoke current session
local function handle_logout()
    local cookie_obj = require("cookie"):new()
    if cookie_obj then
        local fields = cookie_obj:get_all()
        if fields then
            local prefix = (config and config.cookie_prefix) or "verynginx"
            local token = fields[prefix .. "_session"]
            if token then
                require("core.session").revoke(token)
                audit.log("logout", "")
            end
        end
    end
    -- Clear the cookie regardless
    ngx.header["Set-Cookie"] = ((config and config.cookie_prefix) or "verynginx") .. "_session=; Path=/; Max-Age=0"
    return json.encode({ ret = "success" })
end

function _M.register(api)
    api.register("POST", "/login", handle_login, false)
    api.register("POST", "/logout", handle_logout, true)
end

return _M
