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
local dns_cache = require "plugin.proxy_pass.dns_cache"

local function is_ip(host)
    return host and host:match("^%d+%.%d+%.%d+%.%d+$")
end

local rr_idx = {}

local function resolve_host(host)
    if is_ip(host) then
        return host, nil
    end
    local dns_conf = (config and config.proxy and config.proxy.dns) or {}
    local answers, err = dns_cache.resolve(host, "A", dns_conf)
    if not answers or #answers == 0 then
        return nil, err or "dns resolution failed"
    end
    local addrs = dns_cache.extract_addresses(answers)
    if #addrs == 0 then
        return nil, "no A records found"
    end
    rr_idx[host] = (rr_idx[host] or 0) + 1
    return addrs[(rr_idx[host] % #addrs) + 1], nil
end

function _M.on_access(ctx)
    local rules = config.rule and config.rule.proxy_pass
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
            local upstream = config.backend_upstream and config.backend_upstream[rule.upstream]
            if not upstream then
                ngx.log(ngx.ERR, "proxy_pass: upstream '", rule.upstream, "' not found")
                ctx.set_action(ctx, "block", { code = 503, response = "Upstream not found" })
                return
            end

            local node = balancer.select_healthy(upstream, rule.upstream)
            if not node then
                ngx.log(ngx.WARN, "proxy_pass: no healthy node in upstream '", rule.upstream, "'")
                ctx.set_action(ctx, "block", { code = 503, response = "No healthy upstream" })
                return
            end

            -- Resolve hostname to IP (with caching) unless already an IP
            local resolved, err = resolve_host(node.host)
            if not resolved then
                ngx.log(ngx.ERR, "proxy_pass: DNS resolution failed for '", node.host, "': ", err)
                ctx.set_action(ctx, "block", { code = 502, response = "DNS resolution failed" })
                return
            end

            ctx.set_data(ctx, "proxy:target", node.host .. ":" .. (node.port or "80"))
            ctx.set_action(ctx, "proxy", {
                scheme = node.scheme or "http",
                host = resolved,
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