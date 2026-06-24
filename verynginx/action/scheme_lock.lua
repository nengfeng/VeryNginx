-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : scheme lock action - enforce HTTP/HTTPS scheme

local _M = {}

local config = require "core.config"

--- Run scheme lock: if rule matches, redirect to the target scheme.
function _M.run(ctx)
    local rules = config.rule and config.rule.scheme_lock
    if not rules then
        return
    end

    for _, rule in ipairs(rules) do
        if rule.enable == false then
            goto continue
        end

        local matcher_def = rule._matcher_def
        if not matcher_def and type(rule.matcher) == "string" then
            matcher_def = config.matcher and config.matcher[rule.matcher]
        end
        if not matcher_def and type(rule.matcher) == "table" then
            matcher_def = rule.matcher
        end
        if not matcher_def then
            goto continue
        end

        local matcher = require "matcher.init"
        if matcher.test(matcher_def, ctx) then
            local target_scheme = rule.scheme
            local current_scheme = ctx.request.scheme

            if target_scheme and target_scheme ~= current_scheme then
                local target_url = target_scheme .. "://" .. ctx.request.host .. ctx.request.uri
                if ngx.var.query_string and ngx.var.query_string ~= "" then
                    target_url = target_url .. "?" .. ngx.var.query_string
                end
                ctx.set_action(ctx, "redirect", {
                    url = target_url,
                    code = rule.code or 301
                })
                return
            end
        end
        ::continue::
    end
end

return _M