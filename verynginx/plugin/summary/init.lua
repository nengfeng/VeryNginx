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
local ip_reputation = require "core.ip_reputation"
local javascript_verify = require "plugin.browser_verify.javascript_verify"

function _M.on_log(ctx)
    -- Skip statistics for challenge responses (browser verify page)
    if ctx.get_data and ctx.get_data(ctx, "reputation:challenge_response") then
        return
    end

    statistics.log_request(ctx)

    -- IP reputation signal: 404 responses (only from unverified clients)
    local status = tonumber(ngx.var.status) or 0
    if status == 404 then
        if not javascript_verify.check(ctx) then
            ip_reputation.record_signal(ctx.request.remote_addr, "not_found")
        end
    end
end

return _M