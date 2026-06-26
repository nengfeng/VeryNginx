-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : URI rewrite action - internally rewrite request URI based on rules

local _M = {}

local config = require "core.config"

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