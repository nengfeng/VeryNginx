-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : redirect action - issue HTTP redirects based on rules

local _M = {}

local config = require "core.config"

--- Run redirect: if rule matches, issue a redirect to the target URI.
function _M.run(ctx)
    local rules = config.rule and config.rule.redirect
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
            local target = rule.to_uri
            if target then
                ctx.set_action(ctx, "redirect", {
                    url = target,
                    code = rule.code or 302
                })
                return
            end
        end
        ::continue::
    end
end

return _M