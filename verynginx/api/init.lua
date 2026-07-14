-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : API route registration and request dispatching

local _M = {}

local config = require "core.config"
local auth = require "api.auth"
local json = require "dkjson"
local audit = require "core.audit"

-- Precomputed constants (avoids repeated table.concat / json.encode on hot path)
local CSP_HEADER = "default-src 'self'; script-src 'self'; "
    .. "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    .. "connect-src 'self'; frame-ancestors 'self'"
local BODY_UNAUTHORIZED = json.encode({ ret = "failed", message = "unauthorized" })
local BODY_RATE_LIMITED = json.encode({ ret = "failed", message = "too many requests" })
local BODY_CONFLICT = json.encode({ ret = "failed", message = "conflict: duplicate request" })

-- ---------------------------------------------------------------------------
-- Route table: { method, path, auth_required, handler }
-- ---------------------------------------------------------------------------
_M.routes = {}

function _M.register(method, path, handler, auth_required)
    local route = {
        method = method,
        path = path,
        auth_required = (auth_required ~= false),
        handler = handler
    }
    if path:find(":id", 1, true) then
        route._param_pattern = path:gsub(":id", "([^/]+)")
    end
    table.insert(_M.routes, route)
end

-- ---------------------------------------------------------------------------
-- Register routes from domain controllers.
-- Registration order is irrelevant to matching: dispatch() resolves exact
-- routes before parameterized (:id) ones, so e.g. GET /waf/rules/pending is
-- never shadowed by GET /waf/rules/:id regardless of which loads first.
-- ---------------------------------------------------------------------------
local CONTROLLERS = {
    "auth",
    "config",
    "waf_rules",
    "waf_stats",
    "waf_recommender",
    "reputation",
    "geoip",
    "fingerprint",
    "frequency",
    "plugins",
    "kernel_blocking",
}

for _, name in ipairs(CONTROLLERS) do
    require("api.controllers." .. name).register(_M)
end

-- ---------------------------------------------------------------------------
-- Cross-cutting middleware + handler execution for a matched route.
-- ---------------------------------------------------------------------------
local function run_route(route, ctx, method, path)
    -- Auth check
    if route.auth_required then
        if not auth.middleware(ctx) then
            ngx.status = 401
            ctx.set_action(ctx, "response", {
                code = 401,
                response = {
                    code = 401,
                    content_type = "application/json; charset=utf-8",
                    body = BODY_UNAUTHORIZED
                }
            })
            return
        end
    end

    -- Rate limiting for authenticated routes (login has its own)
    if route.auth_required then
        local rl = require "api.rate_limit"
        local user = ctx and ctx.get_data and ctx.get_data(ctx, "auth:user") or "unknown"
        local rl_key = "api:" .. method .. ":" .. path .. ":" .. tostring(user)
        local limit, window = 60, 60
        if method == "POST" and path == "/config" then
            limit, window = 30, 60
        end
        if not rl.allow(rl_key, limit, window) then
            ngx.status = 429
            ctx.set_action(ctx, "response", {
                code = 429,
                response = {
                    code = 429,
                    content_type = "application/json; charset=utf-8",
                    body = BODY_RATE_LIMITED
                }
            })
            return
        end
    end

    -- Rate limiting for unauthenticated routes (by IP)
    if not route.auth_required then
        local rl = require "api.rate_limit"
        local client_ip = ngx.var.remote_addr or "unknown"
        local rl_key = "api:" .. method .. ":" .. path .. ":" .. client_ip
        if not rl.allow(rl_key, 20, 60) then
            ngx.status = 429
            ctx.set_action(ctx, "response", {
                code = 429,
                response = {
                    code = 429,
                    content_type = "application/json; charset=utf-8",
                    body = BODY_RATE_LIMITED
                }
            })
            return
        end
    end

    -- Idempotency key check for mutating requests
    if method ~= "GET" and method ~= "HEAD" and method ~= "OPTIONS" then
        local idem_key = ngx.req.get_headers()["Idempotency-Key"]
        if idem_key and idem_key ~= "" then
            local shared = ngx.shared.vn_locks
            if shared then
                local cache_key = "idempotent:" .. ngx.md5(idem_key)
                if shared:get(cache_key) then
                    ngx.status = 409
                    ctx.set_action(ctx, "response", {
                        code = 409,
                        response = {
                            code = 409,
                            content_type = "application/json; charset=utf-8",
                            body = BODY_CONFLICT
                        }
                    })
                    return
                end
                shared:set(cache_key, true, 3600)
            end
        end
    end

    -- Reset status so a previous route's 404 doesn't leak through
    ngx.status = 200

    -- Security headers
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    ngx.header["X-Frame-Options"] = "SAMEORIGIN"
    ngx.header["X-XSS-Protection"] = "1; mode=block"
    ngx.header["Content-Security-Policy"] = CSP_HEADER

    local ok, response = pcall(route.handler)
    if not ok then
        ngx.log(ngx.ERR, "api dispatch error: ", tostring(response))
        ngx.status = 500
        response = json.encode({ ret = "failed", message = "internal error: " .. tostring(response) })
    end
    if not ngx.status or ngx.status == 0 then
        ngx.status = 200
    end

    -- Response size limit
    local max_response_size = 10485760
    if response and #response > max_response_size then
        ngx.status = 413
        response = json.encode({ ret = "failed", message = "response too large" })
    end

    -- Audit log for mutating operations
    if method ~= "GET" and method ~= "HEAD" and method ~= "OPTIONS" then
        local user = ctx and ctx.get_data and ctx.get_data(ctx, "auth:user") or "-"
        audit.log(method, path .. " status=" .. tostring(ngx.status), user)
    end

    ctx.set_action(ctx, "response", {
        code = ngx.status,
        response = {
            code = ngx.status,
            content_type = ngx.header.content_type or "application/json; charset=utf-8",
            body = response or ""
        }
    })
end

-- ---------------------------------------------------------------------------
-- Request dispatcher. Two-pass match: exact routes take precedence over
-- parameterized (:id) routes so exact paths are never shadowed.
-- ---------------------------------------------------------------------------
function _M.dispatch(ctx)
    local uri = (ctx and ctx.request and ctx.request.uri) or ngx.var.uri
    local base_uri = (config and config.base_uri) or "/verynginx"
    local method = ngx.req.get_method()

    -- Only handle requests under base_uri
    if uri:find(base_uri, 1, true) ~= 1 then
        return
    end

    local path = uri:sub(#base_uri + 1)
    if path == "" then
        path = "/"
    end

    -- Pass 1: exact path match
    for _, route in ipairs(_M.routes) do
        if route.method == method and route.path == path then
            return run_route(route, ctx, method, path)
        end
    end

    -- Pass 2: parameterized (:id) match
    for _, route in ipairs(_M.routes) do
        if route.method == method and route._param_pattern then
            local capture = path:match("^" .. route._param_pattern .. "$")
            if capture then
                ngx.ctx.waf_rule_id = capture
                return run_route(route, ctx, method, path)
            end
        end
    end
end

return _M
