-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : DNS cache - A/AAAA record caching with TTL coverage and stale-if-error

local _M = {}
local resolver = require "resty.dns.resolver"
local json = require "dkjson"

--- Generate a DNS cache key.
-- @param host string: domain name (lowercased)
-- @param record_type string: "A" or "AAAA" (default "A")
-- @return string: cache key
function _M.cache_key(host, record_type)
    return "dns:" .. string.lower(host) .. ":" .. (record_type or "A")
end

--- Resolve a hostname, with caching.
-- @param host string: domain name
-- @param record_type string: "A" or "AAAA" (default "A")
-- @param dns_conf table: { min_ttl, max_ttl, stale_if_error, nameservers? }
-- @return table|nil: DNS answers, or nil on failure
-- @return string|nil: error message on failure
function _M.resolve(host, record_type, dns_conf)
    dns_conf = dns_conf or {}
    record_type = record_type or "A"

    local key = _M.cache_key(host, record_type)
    local shared = ngx.shared.dns_cache
    if shared then
        local cached = shared:get(key)
        if cached then
            local ok, ans = pcall(json.decode, cached)
            if ok and ans then
                return ans
            end
            -- Corrupted cache: remove and re-resolve
            shared:delete(key)
        end
    end

    -- Resolve via DNS
    local nameservers = dns_conf.nameservers or { "8.8.8.8", "1.1.1.1" }
    local r, err = resolver:new({
        nameservers = nameservers,
        retrans = 5,
        timeout = 2000
    })
    if not r then
        return _M.resolve_stale(key, dns_conf), "resolver init failed: " .. tostring(err)
    end

    local answers, err = r:query(host, { qtype = record_type })
    if not answers or #answers == 0 then
        return _M.resolve_stale(key, dns_conf), "dns query failed: " .. tostring(err)
    end

    local ttl = _M.effective_ttl(answers, dns_conf)
    local encoded = json.encode(answers)
    if shared then
        shared:set(key, encoded, ttl)
        shared:set(key .. ":stale", encoded, ttl + (dns_conf.stale_if_error or 60))
    end
    return answers
end

--- Calculate effective TTL bounded by min and max.
function _M.effective_ttl(answers, dns_conf)
    local ttl = 30
    if answers and #answers > 0 and answers[1].ttl then
        ttl = answers[1].ttl
    end
    ttl = math.max(ttl, dns_conf.min_ttl or 5)
    ttl = math.min(ttl, dns_conf.max_ttl or 300)
    return ttl
end

--- Resolve from stale cache when fresh resolution fails.
function _M.resolve_stale(key, dns_conf)
    if (dns_conf.stale_if_error or 0) <= 0 then
        return nil
    end
    local shared = ngx.shared.dns_cache
    if not shared then
        return nil
    end
    local stale = shared:get(key .. ":stale")
    if not stale then
        return nil
    end
    local ok, ans = pcall(json.decode, stale)
    if ok and ans then
        ngx.log(ngx.WARN, "dns_cache: using stale data for ", key)
        return ans
    end
    return nil
end

--- Invalidate a cached entry (call on config/upstream change).
function _M.invalidate(host, record_type)
    local shared = ngx.shared.dns_cache
    if not shared then
        return
    end
    local key = _M.cache_key(host, record_type)
    shared:delete(key)
    shared:delete(key .. ":stale")
end

--- Extract IP addresses from DNS answers.
function _M.extract_addresses(answers)
    if not answers then
        return {}
    end
    local addrs = {}
    for _, ans in ipairs(answers) do
        if ans.address then
            table.insert(addrs, ans.address)
        end
    end
    return addrs
end

return _M