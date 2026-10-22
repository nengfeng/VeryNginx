-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : frequency limit dimension builder
--
-- ONE counter namespace. build_key() returns the DIMENSION ONLY, encoded with
-- a length prefix; the caller assembles the full storage key
-- (ip_encoding.count_key).
--
-- There used to be a second, raw namespace ("fl:v1:<id>:ip:<value>") selected
-- at runtime. It was not a different policy: both built the dimension from
-- the same _dimension_value(), so IP canonicalisation and URI normalisation
-- were identical, and the only difference was the encoding. The raw encoding
-- could not tell two dimension splits apart — host="a" + ip=2001:db8::1 and
-- host="a:2001" + ip=db8::1 both produced "fl:v1:r1:combo:a:2001:db8::1".

local _M = {}

local ip_enc = require "core.kernel_blocking.ip_encoding"

--- Build an encoded rate limit dimension value.
-- The dimension value is length-prefixed so it cannot be confused with the
-- separator, and so two different dimension splits cannot collide.
-- @param key_def string|table: dimension like "ip", "uri", "user", or {"ip","uri"}
-- @param ctx table: request context
-- @return string: LENGTH-PREFIX ENCODED dimension value
function _M.build_key(key_def, ctx)
    if type(key_def) == "table" then
        local parts = {}
        for _, dim in ipairs(key_def) do
            table.insert(parts, ip_enc.encode_dimension(_M._dimension_value(dim, ctx)))
        end
        return table.concat(parts, "")
    end

    local val = _M._dimension_value(key_def, ctx)
    return ip_enc.encode_dimension(val)
end

function _M._dimension_value(dim, ctx)
    if dim == "ip" then
        -- Use canonical IP
        return ip_enc.canonical_ip(ctx.request.remote_addr)
    elseif dim == "uri" then
        -- Use normalized URI to avoid high cardinality
        local statistics = require "core.statistics"
        return statistics.normalize_uri(ctx.request.uri or "/")
    elseif dim == "user" then
        -- Unauthenticated requests must NOT share a single "anonymous" bucket
        -- (that would let any one attacker drain the whole per-user budget and
        -- would also conflate unrelated anonymous visitors). Fall back to the
        -- client IP so each anonymous visitor gets its own bucket.
        return ctx.get_data(ctx, "auth:user") or ip_enc.canonical_ip(ctx.request.remote_addr)
    elseif dim == "host" then
        -- Normalised, not raw. ngx.var.host carries the port, the original
        -- case and IPv6 literal brackets, so the raw value splits one visitor
        -- into several buckets and lets a hostile Host header mint a new
        -- counter key per request.
        local statistics = require "core.statistics"
        return statistics.normalize_host(ctx.request.host)
    else
        return tostring(dim)
    end
end

return _M
