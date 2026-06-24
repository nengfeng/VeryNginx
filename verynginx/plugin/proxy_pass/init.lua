-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : proxy pass plugin - route matched requests to healthy upstream nodes

local _M = {}

_M.name = "proxy_pass"
_M.priority = 500
_M.default_enable = true
_M.critical = true

local config = require "core.config"
local matcher = require "matcher.init"
local balancer = require "plugin.proxy_pass.balancer"

function _M.on_access(ctx)
    local rules = config.rule and config.rule.proxy_pass
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
            local upstream = config.backend_upstream and config.backend_upstream[rule.upstream]
            if not upstream then
                ngx.log(ngx.ERR, "proxy_pass: upstream '", rule.upstream, "' not found")
                ctx.set_action(ctx, "block", { code = 503, response = "Upstream not found" })
                return
            end

            local node = balancer.select_healthy(upstream)
            if not node then
                ngx.log(ngx.WARN, "proxy_pass: no healthy node in upstream '", rule.upstream, "'")
                ctx.set_action(ctx, "block", { code = 503, response = "No healthy upstream" })
                return
            end

            ctx.set_data(ctx, "proxy:target", node.host .. ":" .. (node.port or "80"))
            ctx.set_action(ctx, "proxy", {
                scheme = node.scheme or "http",
                host = node.host,
                port = node.port or "80",
                proxy_host = rule.proxy_host or node.host,
                sni = rule.sni or node.sni or node.host,
                websocket = rule.websocket == true,
            })
            return
        end
        ::continue::
    end
end

return _M