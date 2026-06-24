-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : status API controller - runtime status query

local _M = {}
local dkjson = require "dkjson"

function _M.status()
    local info = {
        ret = "success",
        time = ngx.now(),
        connections_active = ngx.var.connections_active,
        connections_reading = ngx.var.connections_reading,
        connections_writing = ngx.var.connections_writing,
        connections_waiting = ngx.var.connections_waiting,
        config_version = require("core.config").schema.version,
    }
    return dkjson.encode(info)
end

return _M