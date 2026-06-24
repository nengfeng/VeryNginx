-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : upstream health check - Phase 5+ implementation

local _M = {}

function _M.init()
    -- Phase 5: start health check timer
end

function _M.is_healthy(upstream_name, node)
    -- Phase 5: check shared dict health state
    return true
end

return _M