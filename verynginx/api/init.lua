-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : API route registration and request dispatching

local _M = {}

local config = require "core.config"
local auth = require "api.auth"
local json = require "dkjson"
local util = require "util"

-- ---------------------------------------------------------------------------
-- Route table: { method, path, auth_required, handler }
-- ---------------------------------------------------------------------------
_M.routes = {}

function _M.register(method, path, handler, auth_required)
    table.insert(_M.routes, {
        method = method,
        path = path,
        auth_required = (auth_required ~= false),
        handler = handler
    })
end

-- ---------------------------------------------------------------------------
-- Default route handlers
-- ---------------------------------------------------------------------------

--- POST /login - authenticate and return session token
local function handle_login()
    local args = util.get_request_args()
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
        return json.encode({ ret = "failed", message = result })
    end

    auth.set_session_cookie(result)
    ngx.status = 200
    return json.encode({ ret = "success", token = result })
end

--- POST /config - update config
local function handle_set_config()
    -- Rate limit config saves
    local rl = require "api.rate_limit"
    if not rl.allow("config_save:" .. (ngx.var.remote_addr or ""), 30, 60) then
        ngx.status = 429
        return json.encode({ ret = "failed", message = "too many requests" })
    end

    ngx.req.read_body()
    local content_type = ngx.var.content_type or ""
    local raw_body = ngx.req.get_body_data()
    if not raw_body or raw_body == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end

    local new_config

    -- Support both JSON body and form-encoded + base64
    if content_type:find("application/json", 1, true) then
        new_config = json.decode(raw_body)
    else
        local args, err = ngx.req.get_post_args()
        if args and args.config then
            local decoded = ngx.decode_base64(args.config)
            if decoded then
                local unescaped = ngx.unescape_uri(decoded)
                new_config = json.decode(unescaped)
            end
        end
    end

    if not new_config then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid config" })
    end

    local ok, err = require("core.config").save(new_config)
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = err })
    end

    return json.encode({ ret = "success" })
end

--- GET /status - return runtime status
local function handle_get_status()
    local status_info = {
        ret = "success",
        time = ngx.now(),
        connections_active = ngx.var.connections_active,
        connections_reading = ngx.var.connections_reading,
        connections_writing = ngx.var.connections_writing,
        connections_waiting = ngx.var.connections_waiting,
    }
    return json.encode(status_info)
end

--- GET /metrics - return Prometheus metrics
local function handle_get_metrics()
    ngx.header["Content-Type"] = "text/plain; version=0.0.4"
    return require("core.metrics").export_prometheus()
end

--- GET /summary - return request statistics
local function handle_get_summary()
    local args = ngx.req.get_uri_args()
    return require("core.statistics").report(args.type or "short")
end

--- GET /csrf - return a CSRF token (stored in session for later verification)
local function handle_get_csrf()
    local ctx = ngx.ctx.vn_ctx
    if not ctx then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "no request context" })
    end
    local csrf = require "api.csrf"
    local token = csrf.generate(ctx)
    return json.encode({ ret = "success", csrf_token = token })
end

--- GET /config - sanitize config dump (remove password hashes)
local function handle_get_config()
    local raw = require("core.config").report()
    local ok, decoded = pcall(json.decode, raw)
    if ok and decoded and decoded.admin then
        for _, a in ipairs(decoded.admin) do
            a.password_hash = "(redacted)"
        end
    end
    if ok then
        return json.encode(decoded)
    end
    return raw
end

-- ---------------------------------------------------------------------------
-- Register default routes
-- ---------------------------------------------------------------------------
_M.register("POST", "/login", handle_login, false)
_M.register("GET", "/config", handle_get_config, true)
_M.register("POST", "/config", handle_set_config, true)
_M.register("GET", "/status", handle_get_status, true)
_M.register("GET", "/metrics", handle_get_metrics, false)
_M.register("GET", "/summary", handle_get_summary, true)
_M.register("GET", "/csrf", handle_get_csrf, true)

-- ---------------------------------------------------------------------------
-- Router plugin hook: dispatched from plugin/router/init.lua
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

    for _, route in ipairs(_M.routes) do
        if route.method == method and route.path == path then
            ngx.header.content_type = "application/json; charset=utf-8"

            -- Auth check
            if route.auth_required then
                if not auth.middleware(ctx) then
                    ngx.status = 401
                    ctx.set_action(ctx, "response", {
                        code = 401,
                        response = {
                            code = 401,
                            content_type = "application/json; charset=utf-8",
                            body = json.encode({ ret = "failed", message = "unauthorized" })
                        }
                    })
                    return
                end
            end

            local response = route.handler()
            if not ngx.status or ngx.status == 0 then
                ngx.status = 200
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
    end

    -- No route matched: treat as static file request
    -- The nginx config will serve these via /verynginx/static/ location
end

return _M