-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : load balancer - select healthy node (access phase) + set_current_peer (balancer phase)

local _M = {}

local health_check = require "plugin.proxy_pass.health_check"

--- Select a healthy node from the upstream.
-- Called from proxy_pass plugin during access phase.
-- @param upstream table: upstream config from backend_upstream
-- @return table|nil: { scheme, host, port, weight } or nil if no healthy nodes
function _M.select_healthy(upstream)
    if not upstream or not upstream.nodes then
        return nil
    end

    local healthy_nodes = {}
    for _, node in ipairs(upstream.nodes) do
        if health_check.is_healthy(upstream, node) then
            table.insert(healthy_nodes, node)
        end
    end

    if #healthy_nodes == 0 then
        return nil
    end

    local method = upstream.method or "round_robin"

    if method == "ip_hash" then
        return _M._ip_hash(healthy_nodes, upstream)
    elseif method == "weighted_random" then
        return _M._weighted_random(healthy_nodes)
    else
        return _M._round_robin(healthy_nodes, upstream)
    end
end

-- ---------------------------------------------------------------------------
-- Load balancing algorithms
-- ---------------------------------------------------------------------------

function _M._round_robin(nodes, upstream)
    upstream._rr_index = (upstream._rr_index or 0) + 1
    if upstream._rr_index > #nodes then
        upstream._rr_index = 1
    end
    return nodes[upstream._rr_index]
end

function _M._ip_hash(nodes, upstream)
    local client_ip = ngx.var.remote_addr or "127.0.0.1"
    local hash = ngx.crc32_short(client_ip)
    local index = (hash % #nodes) + 1
    return nodes[index]
end

function _M._weighted_random(nodes)
    local total_weight = 0
    for _, node in ipairs(nodes) do
        total_weight = total_weight + (node.weight or 1)
    end
    local r = math.random(1, total_weight)
    local sum = 0
    for _, node in ipairs(nodes) do
        sum = sum + (node.weight or 1)
        if r <= sum then
            return node
        end
    end
    return nodes[#nodes]
end

-- ---------------------------------------------------------------------------
-- balancer_by_lua phase: read pre-selected target and set peer
-- ---------------------------------------------------------------------------
function _M.run()
    local host = ngx.var.vn_proxy_host
    local port = tonumber(ngx.var.vn_proxy_port)

    if not host or host == "" then
        ngx.log(ngx.ERR, "balancer: vn_proxy_host is empty")
        return ngx.exit(500)
    end
    if not port then
        port = 80
    end

    local ngx_balancer = require "ngx.balancer"
    local ok, err = ngx_balancer.set_current_peer(host, port)
    if not ok then
        ngx.log(ngx.ERR, "balancer: set_current_peer failed: ", err)
        return ngx.exit(502)
    end
end

return _M