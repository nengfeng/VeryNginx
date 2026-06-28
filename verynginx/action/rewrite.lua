-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : URI rewrite action - internally rewrite request URI based on rules

local _M = {}

local config = require "core.config"
local matcher = require "matcher.init"

--- Run URI rewrite: if rule matches, rewrite the request URI.
function _M.run(ctx)
    local rules = config.rule and config.rule.uri_rewrite
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
            local uri = ctx.request.uri

            -- Apply regex replacement if specified
            if rule.replace_re and rule.to_uri then
                local new_uri, _ = ngx.re.gsub(uri, rule.replace_re, rule.to_uri, "isjo")
                if new_uri and new_uri ~= uri then
                    ctx.set_action(ctx, "rewrite", { uri = new_uri })
                    return
                end
            elseif rule.to_uri then
                -- Static rewrite
                ctx.set_action(ctx, "rewrite", { uri = rule.to_uri })
                return
            end
        end
        ::continue::
    end
end

return _M