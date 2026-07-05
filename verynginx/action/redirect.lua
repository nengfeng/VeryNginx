-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : redirect action - issue HTTP redirects based on rules

local _M = {}

local config = require "core.config"
local matcher = require "matcher.init"

--- Run redirect: if rule matches, issue a redirect to the target URI.
function _M.run(ctx)
    local rules = config.rule.redirect
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