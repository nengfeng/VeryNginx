-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : management path router - dispatch API requests or serve dashboard static files

local _M = {}

_M.name = "router"
_M.priority = 400
_M.default_enable = true
_M.critical = false

local config = require "core.config"
local api = require "api.init"

function _M.on_access(ctx)
    local base_uri = (config and config.base_uri) or "/verynginx"
    local uri = ctx.request.uri

    if uri:find(base_uri, 1, true) ~= 1 then
        return
    end

    ctx.set_data(ctx, "router:target", "management")

    -- Try API dispatch first. If dispatch() handles it (finds a route),
    -- it sets an action on ctx. If no route matches, it returns normally.
    api.dispatch(ctx)

    -- Dispatch handled the request (auth or route handler set an action)
    if ctx.has_decision(ctx) then
        return
    end

    -- No API route matched: serve dashboard static files
    local static_path = uri:sub(#base_uri + 1)

    -- Sanitize: reject URL-encoded traversal sequences and ../
    static_path = ngx.unescape_uri(static_path)
    if static_path:find("%.%.", 1, true) or static_path:find("\0") then
        ngx.status = 403
        return ngx.exit(403)
    end

    if static_path == "" or static_path == "/" then
        static_path = "/index.html"
    end

    -- Derive dashboard directory from installation prefix
    local dash_path = config.resolve_path() .. "dashboard"
    -- Ensure path has no trailing double slashes
    dash_path = dash_path:gsub("/+$", "")

    ctx.set_action(ctx, "static", {
        root = dash_path,
        path = static_path,
        expires = "epoch"
    })
end

return _M