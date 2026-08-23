-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : authentication middleware - pluggable strategies, CSRF, rate limiting

local _M = {}

local config = require "core.config"
local session = require "core.session"
local password_hash = require "core.password_hash"
local rate_limit = require "api.rate_limit"
local csrf = require "api.csrf"
local cookie = require "cookie"

-- ---------------------------------------------------------------------------
-- Auth strategy registry
-- ---------------------------------------------------------------------------
_M.strategies = {}

function _M.register(name, strategy)
    _M.strategies[name] = strategy
end

-- ---------------------------------------------------------------------------
-- Default session-based strategy
-- ---------------------------------------------------------------------------
_M.strategies["session"] = {
    check = function(ctx)
        local cookie_obj = cookie:new()
        if not cookie_obj then
            return false
        end
        local fields = cookie_obj:get_all()
        if not fields then
            return false
        end

        local prefix = (config and config.cookie_prefix) or "verynginx"
        local token = fields[prefix .. "_session"]
        if not token then
            return false
        end

        local secret = config.security.session_secret
        -- Fail closed on empty/short secrets: HMAC with "" is forgeable
        -- offline ("" is truthy in Lua, so `if not secret` passed it before).
        if not secret or #secret < 16 then
            ngx.log(ngx.ERR, "auth: session_secret missing or too short (<16); set security.session_secret")
            return false
        end

        local ok, payload = session.verify(token, secret)
        if not ok then
            return false
        end

        -- Verify user still exists and is enabled
        local admins = config and config.admin or {}
        for _, admin in ipairs(admins) do
            if admin.user == payload.user and admin.enable ~= false then
                if ctx and ctx.set_data then
                    ctx.set_data(ctx, "auth:user", payload.user)
                end
                return true
            end
        end

        return false
    end,

    login = function(user, password)
        local shared = ngx.shared.vn_session

        -- Account lock check (per-user, independent of IP)
        if shared then
            local lock_key = "account_lock:" .. tostring(user)
            if shared:get(lock_key) then
                return false, "account_locked"
            end
        end

        -- Rate limit by client IP (trust nginx real_ip_from; do NOT
        -- parse X-Forwarded-For directly — it can be forged by client)
        local client_ip = ngx.var.remote_addr or "unknown"
        local rl_key = "login:" .. client_ip
        if not rate_limit.allow(rl_key, 30, 60) then
            return false, "too_many_attempts"
        end
        -- Also rate-limit per username (prevents brute-force even with changing IPs)
        local user_rl_key = "login_user:" .. tostring(user)
        if not rate_limit.allow(user_rl_key, 5, 60) then
            return false, "too_many_attempts"
        end

        local admins = config and config.admin or {}
        for _, admin in ipairs(admins) do
            if admin.user == user and admin.enable ~= false then
                if password_hash.verify(password, admin.password_hash) then
                    -- Clear any account lock on success
                    if shared then
                        shared:delete("account_lock:" .. tostring(user))
                        shared:delete("failed_login:" .. tostring(user))
                    end
                    local payload = {
                        user = user,
                        expire_at = ngx.time() + ((config.security.session_ttl) or 28800),
                        nonce = require("core.random").bytes(16)
                    }
                    local secret = config.security.session_secret
                    if not secret or #secret < 16 then
                        return false, "session_secret missing or too short (<16)"
                    end
                    local token = session.sign(payload, secret)
                    return true, token
                end
            end
        end

        -- Track failed attempts per user (account lockout)
        if shared then
            local fail_key = "failed_login:" .. tostring(user)
            local attempts = shared:incr(fail_key, 1, 1, 300)
            if attempts and attempts >= 5 then
                shared:set("account_lock:" .. tostring(user), true, 900)
                shared:delete(fail_key)
            end
        end

        return false, "invalid_credentials"
    end,

    logout = function(_)
        -- Clear session cookie is handled by the API controller
    end
}

-- ---------------------------------------------------------------------------
-- Check if a request is a mutating (non-GET) request
-- ---------------------------------------------------------------------------
function _M.is_mutating_request(ctx)
    local method = (ctx and ctx.request and ctx.request.method) or ngx.req.get_method()
    return method ~= "GET" and method ~= "HEAD" and method ~= "OPTIONS"
end

-- ---------------------------------------------------------------------------
-- Auth middleware: verify session + CSRF for mutating requests
-- ---------------------------------------------------------------------------
function _M.middleware(ctx)
    local strategy_name = (config and config.auth_strategy) or "session"
    local strategy = _M.strategies[strategy_name]

    if not strategy then
        ngx.log(ngx.ERR, "auth: strategy not found: ", strategy_name)
        return false
    end

    if not strategy.check(ctx) then
        return false
    end

    -- CSRF check for mutating requests
    if _M.is_mutating_request(ctx) and not csrf.verify(ctx) then
        return false
    end

    return true
end

-- ---------------------------------------------------------------------------
-- Set secure cookie headers for session cookie
-- ---------------------------------------------------------------------------
function _M.set_session_cookie(token)
    local prefix = (config and config.cookie_prefix) or "verynginx"
    local cookie_str = prefix .. "_session=" .. token .. "; Path=/; HttpOnly; SameSite=Strict"
    if ngx.var.scheme == "https" then
        cookie_str = cookie_str .. "; Secure"
    end
    ngx.header["Set-Cookie"] = cookie_str
end

return _M