-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : browser verification via cookie challenge

local _M = {}

local config = require "core.config"
local random = require "core.random"
local util = require "util"

-- Signature validity window (seconds). The cookie carries no time component
-- by itself; the server binds the signature to a rolling time slot so a
-- solved cookie cannot be replayed indefinitely (Issue B). Browser-side
-- Max-Age stays 600; this adds a server-side expiry (~1-2 slots).
local VALIDITY = 600

local function _get_seed()
    -- Nil-safe: config.security may be absent after a failed config load;
    -- this runs at require time (_fallback_seed) and must never raise.
    local s = ((config and config.security) and config.security.session_secret) or nil
    if type(s) == "string" and #s > 0 then
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

local function current_slot()
    return math.floor(ngx.time() / VALIDITY)
end

--- Compute verification signature for a given mark.
-- Uses session_secret if configured, otherwise a random per-worker seed.
-- The signature is bound to a rolling time slot so the server can expire it.
local function sign(ctx, mark, slot)
    slot = slot or current_slot()
    local ua = ngx.var.http_user_agent or ""
    local secret = config and config.security and config.security.session_secret or nil
    -- Empty string guard: "" is truthy in Lua and would replace the fallback.
    local seed = (type(secret) == "string" and #secret > 0 and secret) or _fallback_seed
    return ngx.md5("VN" .. slot .. ctx.request.remote_addr .. ua .. mark .. seed)
end

--- Check if the request already has a valid verification cookie.
-- Accepts the current and previous slot to avoid mid-flight expiry at a
-- slot boundary.
function _M.check(ctx)
    local hc = ngx.var.http_cookie
    if not hc then
        return false
    end
    local slot = current_slot()
    if hc:find(sign(ctx, "cookie", slot), 1, true) then
        return true
    end
    if hc:find(sign(ctx, "cookie", slot - 1), 1, true) then
        return true
    end
    return false
end

--- Issue a cookie challenge: serve a JS page that sets the verification
-- cookie CLIENT-SIDE on execution (never via Set-Cookie — otherwise a script
-- bot that simply follows the redirect obtains a valid cookie without running
-- any JS, defeating the challenge entirely).
--
-- Sets a 200 response for rule_engine to finalize (outside pcall). Do NOT call
-- ngx.exit()/ngx.redirect() directly (AGENTS.md 1.1).
function _M.challenge(ctx)
    local path = require("core.config").resolve_path():match("(.+/)lua_script/")
        or "/opt/verynginx/"
    path = path:gsub("lua_script/", "") .. "support/verify_javascript.html"
    local f = io.open(path, "r")
    local verify_html
    if f then
        verify_html = f:read("*all")
        f:close()
    else
        verify_html = "<html><body><script>document.cookie='INFOCOOKIE';location='INFOURI';</script></body></html>"
    end

    local cookie_sign = sign(ctx, "cookie")
    local prefix = (config and config.cookie_prefix) or "verynginx"

    -- Strip CR/LF from the request URI / query before building the redirect
    -- target. Even though the target is injected into the JS challenge page
    -- (HTML/JS-escaped below), a CRLF here is a latent response-splitting /
    -- header-injection vector if the injection context ever changes — so
    -- remove it at the source (defense in depth).
    local uri = (ctx.request.uri or ""):gsub("[\r\n]", "")
    local target = ctx.request.scheme .. "://" .. ctx:get_safe_host() .. uri
    local qs = ngx.var.query_string
    if qs and qs ~= "" then
        target = target .. "?" .. qs:gsub("[\r\n]", "")
    end
    if not (target:match("^https?://") or target:match("^/")) then
        target = "/"
    end
    target = (target:gsub('[\\"\'<>/\r\n]', {
        ['\\'] = '\\\\', ['"'] = '\\x22', ["'"] = '\\x27',
        ['<'] = '\\x3C', ['>'] = '\\x3E', ['/'] = '\\x2F',
        ['\r'] = '\\r', ['\n'] = '\\n',
    }))

    local html = verify_html
    html = html:gsub("INFOCOOKIE", cookie_sign)
    html = html:gsub("COOKIEPREFIX", prefix)
    html = util.string_replace(html, "INFOURI", target, 1)

    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-cache, no-store, must-revalidate"
    ngx.header["Pragma"] = "no-cache"
    ngx.header["Expires"] = "0"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    ngx.say(html)
    -- ngx.exit(200) is called by rule_engine.apply() outside pcall
end

return _M
