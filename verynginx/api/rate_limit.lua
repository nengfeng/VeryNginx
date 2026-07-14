-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : rate limiter for management API endpoints

local _M = {}

--- Check if a request is allowed within the rate limit.
-- @param key string: unique key (e.g. "login:127.0.0.1")
-- @param limit number: max requests (default 10)
-- @param window number: time window in seconds (default 60)
-- @return boolean: true if allowed, false if rate limited
function _M.allow(key, limit, window)
    limit = limit or 10
    window = window or 60

    local shared = ngx.shared.vn_rate_limit
    if not shared then
        return true
    end

    local count = shared:incr(key, 1, 1, window)
    if not count then
        return true
    end

    return count <= limit
end

--- Parse rate limit string like "10/m", "100/h", "5/s"
-- @param spec string: e.g. "10/m", "100/h"
-- @return number limit, number window_seconds
function _M.parse_spec(spec)
    if not spec then
        return 10, 60
    end
    local count_str, unit = spec:match("^(%d+)/([smh])$")
    if not count_str then
        return 10, 60
    end
    local count = tonumber(count_str)
    local window = unit == "s" and 1 or unit == "m" and 60 or unit == "h" and 3600 or 60
    return count, window
end

return _M