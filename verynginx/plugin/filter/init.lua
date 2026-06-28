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
local waf_manager = require "waf-rule-manager"

function _M.on_access(ctx)
    -- Load rules from WAF rule manager (shared dict cache + file fallback)
    local rules_obj = waf_manager.load_rules()
    local rules
    if rules_obj and rules_obj.rules and #rules_obj.rules > 0 then
        rules = rules_obj.rules
    else
        -- Fallback to hardcoded default rules
        local fallback_rules = require("plugin.filter.rules")
        rules = fallback_rules.load_rules()
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

        -- Rate limit check (only applies to matched requests)
        if not waf_manager.check_rate_limit(rule.id, rule) then
            goto continue
        end

        -- Record hit statistics (async, non-blocking)
        waf_manager.record_hit(rule.id, ctx)

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
        elseif rule.action == "log" then
            ngx.log(ngx.WARN, "waf: rule matched [", rule.id, "] ", rule.name, " uri=", ctx.request.uri)
        end
        ::continue::
    end
end

return _M