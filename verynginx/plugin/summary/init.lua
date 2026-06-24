-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : summary plugin - logs request stats via statistics engine

local _M = {}

_M.name = "summary"
_M.priority = 900
_M.default_enable = true
_M.critical = false

local statistics = require "core.statistics"

function _M.on_log(ctx)
    statistics.log_request(ctx)
end

return _M