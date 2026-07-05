-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : frequency limit plugin - rate limit requests by matcher rules

local _M = {}

_M.name = "frequency_limit"
_M.priority = 200
_M.default_enable = true
_M.critical = true

local config = require "core.config"
local matcher = require "matcher.init"
local limiter = require "plugin.frequency_limit.limiter"

function _M.on_access(ctx)
    local rules = config.rule.frequency_limit
    if not rules then
        return
    end

    local shared = ngx.shared.frequency_limit
    if not shared then
        return
    end

    for _, rule in ipairs(rules) do
        if rule.enable == false then
            goto continue
        end

        local matcher_def = matcher.resolve(rule)
        if not matcher_def then
            goto continue
        end

        if matcher.test(matcher_def, ctx) then
            local key = limiter.build_key(rule.key or "ip", ctx)
            local limit = rule.limit or 60
            local window = rule.window or 60
            local current = shared:incr(key, 1, 0, window)

            if current and current > limit then
                ctx.set_data(ctx, "frequency_limit:limited", true)
                ctx.set_action(ctx, "block", {
                    code = rule.code or 429,
                    response = rule.response or "Too Many Requests"
                })
                return
            end
        end
        ::continue::
    end
end

return _M