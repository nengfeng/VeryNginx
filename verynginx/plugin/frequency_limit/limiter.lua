-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : frequency limit key builder

local _M = {}

--- Build a rate limit key based on dimension.
-- @param key_def string|table: dimension like "ip", "uri", "user", or {"ip","uri"}
-- @param ctx table: request context
-- @return string: rate limit key with "fl:" prefix
function _M.build_key(key_def, ctx)
    if type(key_def) == "table" then
        local parts = {}
        for _, dim in ipairs(key_def) do
            table.insert(parts, _M._dimension_value(dim, ctx))
        end
        return "fl:combo:" .. table.concat(parts, ":")
    end

    local val = _M._dimension_value(key_def, ctx)
    return "fl:" .. tostring(key_def) .. ":" .. val
end

function _M._dimension_value(dim, ctx)
    if dim == "ip" then
        return ctx.request.remote_addr or "unknown"
    elseif dim == "uri" then
        -- Use normalized URI to avoid high cardinality
        local statistics = require "core.statistics"
        return statistics.normalize_uri(ctx.request.uri or "/")
    elseif dim == "user" then
        return ctx.get_data(ctx, "auth:user") or "anonymous"
    elseif dim == "host" then
        return ctx.request.host or "unknown"
    else
        return tostring(dim)
    end
end

return _M