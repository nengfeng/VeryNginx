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

    -- IP reputation signal: 404 responses (sampled to avoid MD5 flood under scan)
    local status = tonumber(ngx.var.status) or 0
    if status == 404 then
        local ip = ctx.request.remote_addr
        -- Sample: only 1-in-10 404s trigger the full cookie check + signal
        local counter = ngx.shared.ip_reputation:incr("ip_rep:404_sample:" .. ip, 1, 0, 60)
        if counter and (counter % 10) == 1 then
            -- 只对 challenge 触发的 IP（pending 状态）累加 404 信号，
            -- 避免正常用户浏览 404 页面被误判为扫描器（AGENTS.md §4.3）
            if ip_reputation.has_pending(ip) and not javascript_verify.check(ctx) then
                ip_reputation.record_signal(ip, "not_found")
            end
        end
    end
end

return _M