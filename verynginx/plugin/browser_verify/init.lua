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
    local rules = config.rule.browser_verify
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
            local verify_types = rule.type or { "cookie" }
            local cookie_ok, js_ok

            for _, vtype in ipairs(verify_types) do
                if vtype == "cookie" then
                    cookie_ok = cookie_verify.check(ctx)
                    if not cookie_ok then
                        -- Set a TERMINAL challenge action and return. Never issue
                        -- the challenge page here and return without an action:
                        -- this on_access runs inside pcall, and without a terminal
                        -- action the plugin chain (proxy_pass, ...) would continue
                        -- past the challenge, serving the protected resource to
                        -- non-browsers. rule_engine.apply() invokes challenge()
                        -- and ngx.exit(200) outside pcall.
                        ctx.set_action(ctx, "challenge", { cookie_verify = cookie_verify })
                        return
                    end
                elseif vtype == "javascript" then
                    js_ok = javascript_verify.check(ctx)
                    if not js_ok then
                        ctx.set_action(ctx, "challenge", { javascript_verify = javascript_verify })
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