-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : upstream health check - active probe + passive failure counting

local _M = {}
local config = require "core.config"
local metrics = require "core.metrics"

-- ---------------------------------------------------------------------------
-- Key helpers / state key format
-- ---------------------------------------------------------------------------
local function state_key(upstream_name, node)
    return "hc:" .. upstream_name .. ":" .. node.host .. ":" .. tostring(node.port)
end

-- ---------------------------------------------------------------------------
-- Initialization (called from init_worker_by_lua)
-- ---------------------------------------------------------------------------
function _M.init()
    local interval = (config and config.proxy and config.proxy.health_check_interval) or 5
    ngx.timer.every(interval, function()
        _M.active_check_all()
    end)
end

-- ---------------------------------------------------------------------------
-- Active health check: probe all nodes across all upstreams
-- ---------------------------------------------------------------------------
function _M.active_check_all()
    local upstreams = config and config.backend_upstream
    if not upstreams then
        return
    end
    for name, upstream in pairs(upstreams) do
        if upstream.nodes then
            for _, node in ipairs(upstream.nodes) do
                _M.check_node(name, node)
            end
        end
    end
end

--- Check a single node. Sets healthy on success, increments failures on failure.
function _M.check_node(upstream_name, node)
    local ok = _M.probe_node(node)
    local shared = ngx.shared.healthcheck
    if not shared then
        return
    end

    local sk = state_key(upstream_name, node)
    if ok then
        shared:delete(sk .. ":state")
        shared:delete(sk .. ":failures")
        shared:delete(sk .. ":last_error")
        if metrics and metrics.gauge then
            metrics.gauge("upstream_healthy", 1,
                { upstream = upstream_name, node = node.host .. ":" .. tostring(node.port) })
        end
        return
    end

    _M.report_failure(upstream_name, node, "probe failed")
end

--- Probe a single node via TCP or HTTP(S).
function _M.probe_node(node)
    local hc = node.health_check or {}
    local timeout = hc.timeout or 2000  -- ms
    local path = hc.path or "/"
    local use_ssl = (node.scheme or "http") == "https"
    local port = tonumber(node.port) or (use_ssl and 443 or 80)

    if hc.method == "tcp" or not hc.path then
        local sock = ngx.socket.tcp()
        sock:settimeout(timeout)
        local ok, _ = sock:connect(node.host, port)
        if ok and use_ssl then
            ok = sock:sslhandshake()
        end
        sock:close()
        return ok
    end

    -- HTTP(S) probe
    local sock = ngx.socket.tcp()
    sock:settimeout(timeout)
    local ok, err = sock:connect(node.host, port)
    if not ok then
        sock:close()
        return false, err
    end

    if use_ssl then
        ok, err = sock:sslhandshake()
        if not ok then
            sock:close()
            return false, err
        end
    end

    local req = "GET " .. path .. " HTTP/1.0\r\nHost: " .. node.host .. "\r\nConnection: close\r\n\r\n"
    sock:send(req)
    local resp, err2 = sock:receive("*l")
    sock:close()

    if not resp then
        return false, err2
    end
    -- Accept 2xx or 3xx responses as healthy
    local status_code = tonumber(resp:match("HTTP/%d%.%d (%d+)"))
    return status_code and status_code < 400
end

-- ---------------------------------------------------------------------------
-- Passive failure counting
-- ---------------------------------------------------------------------------

--- Report a failure for a node. After max_fails, marks as unhealthy.
function _M.report_failure(upstream_name, node, reason)
    local shared = ngx.shared.healthcheck
    if not shared then
        return
    end

    local sk = state_key(upstream_name, node)
    local max_fails = (node.health_check and node.health_check.max_fails) or 3
    local fail_timeout = (node.health_check and node.health_check.fail_timeout) or 30

    local failures = shared:incr(sk .. ":failures", 1, 0)
    if failures >= max_fails then
        shared:set(sk .. ":state", "unhealthy", fail_timeout)
    end
    shared:set(sk .. ":last_error", reason or "unknown", 60)

    if metrics and metrics.gauge then
        metrics.gauge("upstream_healthy", 0,
            { upstream = upstream_name, node = node.host .. ":" .. tostring(node.port) })
    end
end

-- ---------------------------------------------------------------------------
-- Health status query
-- ---------------------------------------------------------------------------

--- Check if a node is healthy.
-- @param upstream_name string: upstream name
-- @param node table: node config { host, port }
-- @return boolean: true if healthy
function _M.is_healthy(upstream_name, node)
    local shared = ngx.shared.healthcheck
    if not shared then
        return true
    end
    local sk = state_key(upstream_name, node)
    return shared:get(sk .. ":state") ~= "unhealthy"
end

--- Get the last error for a node.
function _M.last_error(upstream_name, node)
    local shared = ngx.shared.healthcheck
    if not shared then
        return nil
    end
    local sk = state_key(upstream_name, node)
    return shared:get(sk .. ":last_error")
end

return _M