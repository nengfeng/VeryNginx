-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : summary API controller - query request statistics

local _M = {}
local statistics = require "core.statistics"

function _M.report(period)
    local data = statistics.report(period)
    return data
end

return _M