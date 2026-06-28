-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : browser verification via cookie challenge

local _M = {}

local config = require "core.config"
local random = require "core.random"

-- Fallback seed: stored in shared dict so all workers use the same seed
-- when session_secret is not configured.
local function _get_seed()
    local s = config.security and config.security.session_secret
    if s and s ~= "" then
        return s
    end
    local shared = ngx.shared.vn_config
    if shared then
        local seed = shared:get("browser_verify_seed")
        if not seed then
            shared:add("browser_verify_seed", random.hex(32))
            seed = shared:get("browser_verify_seed")
        end
        return seed
    end
    return random.hex(32)
end
local _fallback_seed = _get_seed()

--- Compute verification signature for a given mark.
-- Uses session_secret if configured, otherwise a random per-worker seed.
local function sign(ctx, mark)
    local ua = ngx.var.http_user_agent or ""
    local seed = (config.security and config.security.session_secret) or _fallback_seed
    return ngx.md5("VN" .. ctx.request.remote_addr .. ua .. mark .. seed)
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
    local cookie_str = prefix .. "_sign_cookie=" .. cookie_sign .. "; Path=/; HttpOnly; SameSite=Lax"
    ngx.header["Set-Cookie"] = cookie_str

    local target = ctx.request.scheme .. "://" .. ngx.var.http_host .. ctx.request.uri
    if ngx.var.query_string and ngx.var.query_string ~= "" then
        target = target .. "?" .. ngx.var.query_string
    end
    ngx.redirect(target, ngx.HTTP_MOVED_TEMPORARILY)
end

return _M