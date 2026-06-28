-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : WAF filter plugin - rule-based request filtering

local _M = {}

_M.name = "filter"
_M.priority = 100
_M.default_enable = true
_M.critical = true

local config = require "core.config"
local matcher = require "matcher.init"

function _M.on_access(ctx)
    local rules = config.rule and config.rule.filter
    if not rules then
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

        local matched = matcher.test(matcher_def, ctx)
        if not matched then
            goto continue
        end

        if rule.action == "accept" then
            ctx.set_action(ctx, "accept")
            return
        elseif rule.action == "block" then
            ctx.set_data(ctx, "filter:blocked", true)
            ctx.set_action(ctx, "block", {
                code = rule.code or 403,
                response = rule.response
            })
            return
        end
        ::continue::
    end
end

return _M