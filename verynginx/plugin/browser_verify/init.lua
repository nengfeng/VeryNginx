-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : browser verify plugin - cookie and JavaScript challenge verification

local _M = {}

_M.name = "browser_verify"
_M.priority = 300
_M.default_enable = false
_M.critical = true

local config = require "core.config"
local matcher = require "matcher.init"
local cookie_verify = require "plugin.browser_verify.cookie_verify"
local javascript_verify = require "plugin.browser_verify.javascript_verify"

function _M.on_access(ctx)
    local rules = config.rule and config.rule.browser_verify
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

        if matcher.test(matcher_def, ctx) then
            local verify_types = rule.type or { "cookie" }
            local cookie_ok, js_ok = false, false

            for _, vtype in ipairs(verify_types) do
                if vtype == "cookie" then
                    cookie_ok = cookie_verify.check(ctx)
                    if not cookie_ok then
                        cookie_verify.challenge(ctx)
                        return
                    end
                elseif vtype == "javascript" then
                    js_ok = javascript_verify.check(ctx)
                    if not js_ok then
                        javascript_verify.challenge(ctx)
                        return
                    end
                end
            end

            ctx.set_data(ctx, "browser_verify:passed", true)
            return
        end
        ::continue::
    end
end

return _M