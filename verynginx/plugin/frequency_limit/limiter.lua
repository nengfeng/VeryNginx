-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : frequency limit key builder + v2 namespace support
--
-- v1 (legacy): build_key() returns full key like "fl:ip:1.2.3.4"
-- v2 (post-migration): build_key_v2(ctx) returns ENCODED dimension-only
--   value, and the caller assembles:
--     fl:v2:count:<encoded_rule_id>:<encoded_dimension>

local _M = {}

local ip_enc = require "core.kernel_blocking.ip_encoding"

--- Build a rate limit key based on dimension (full, v1 format).
-- @param key_def string|table: dimension like "ip", "uri", "user", or {"ip","uri"}
-- @param ctx table: request context
-- @return string: rate limit key with "fl:" prefix (legacy v1)
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

--- Build a v2 dimension value (encoded, no prefix).
-- Used when migration is complete and all rules use v2 namespace.
-- @param key_def string|table: dimension like "ip", "uri", "user", or {"ip","uri"}
-- @param ctx table: request context
-- @return string: LENGTH-PREFIX ENCODED dimension value
function _M.build_key_v2(key_def, ctx)
    if type(key_def) == "table" then
        local parts = {}
        for _, dim in ipairs(key_def) do
            local val = _M._dimension_value(dim, ctx)
            table.insert(parts, ip_enc.encode_dimension(val))
        end
        return table.concat(parts, "")
    end

    local val = _M._dimension_value(key_def, ctx)
    return ip_enc.encode_dimension(val)
end

function _M._dimension_value(dim, ctx)
    if dim == "ip" then
        -- Use canonical IP for v2
        return ip_enc.canonical_ip(ctx.request.remote_addr)
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
