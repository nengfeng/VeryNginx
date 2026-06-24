-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : metrics API controller - Prometheus metrics export

local _M = {}
local metrics = require "core.metrics"

function _M.export()
    ngx.header["Content-Type"] = "text/plain; version=0.0.4"
    return metrics.export_prometheus()
end

return _M