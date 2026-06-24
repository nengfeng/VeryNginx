-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : management path router - identify and dispatch admin requests

local _M = {}

_M.name = "router"
_M.priority = 400
_M.default_enable = true
_M.critical = false

local config = require "core.config"

function _M.on_access(ctx)
    local base_uri = (config and config.base_uri) or "/verynginx"
    local uri = ctx.request.uri

    if uri:find(base_uri, 1, true) ~= 1 then
        return
    end

    -- Mark this as a management request
    ctx.set_data(ctx, "router:target", "management")

    -- Dispatch to the API handler
    local api = require "api.init"
    api.dispatch(ctx)
end

return _M