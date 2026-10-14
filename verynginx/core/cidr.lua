-- -*- coding: utf-8 -*-
-- IPv4 CIDR matching.
--
-- Extracted verbatim from ip_reputation's allow-list path so the verified-
-- crawler range list shares ONE implementation with it. Two copies of
-- security-relevant matching logic is how allow-lists silently start
-- disagreeing with each other; the move is behaviour-preserving (same parse
-- cache, same bit math) and ip_reputation's spec suite covers it.
--
-- IPv6 is NOT handled here. is_whitelisted deliberately rejected v6 CIDR
-- entries (validate_whitelist_entry) rather than accept one it cannot match,
-- and that reasoning applies to the crawler list too.

local _M = {}

local bit = require "core.bit_compat"

-- Worker-local CIDR parse cache: the parsed subnet+mask depend only on the
-- CIDR string, which is immutable for a given list entry, so this never goes
-- stale even when the list is hot-reloaded. Avoids re-running the string
-- regex + mask loop for every IP lookup against every entry.
local cidr_parse_cache = {}

local function parse_ipv4(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    return (tonumber(a) * 16777216) + (tonumber(b) * 65536) + (tonumber(c) * 256) + tonumber(d)
end

_M.parse_ipv4 = parse_ipv4

local function cidr_mask(cidr)
    local parsed = cidr_parse_cache[cidr]
    if parsed ~= nil then return parsed end
    local result
    local pos = cidr:find("/")
    if pos then
        local subnet = parse_ipv4(cidr:sub(1, pos - 1))
        local bits = tonumber(cidr:sub(pos + 1))
        if subnet and bits then
            local mask = 0
            for _ = 1, bits do
                mask = (mask * 2) + 1
            end
            result = { subnet = subnet, mask = mask * (2 ^ (32 - bits)) }
        end
    end
    cidr_parse_cache[cidr] = result
    return result
end

--- Does `ip` fall inside `cidr`? A bare address is accepted as a /32.
-- Returns false (never an error) for anything unparseable, so a malformed
-- entry in a config list degrades to "does not match" instead of throwing on
-- the request path.
function _M.ip_in_cidr(ip, cidr)
    if ip == cidr then
        return true
    end
    local ip_num = parse_ipv4(ip)
    if not ip_num then return false end
    local c = cidr_mask(cidr)
    if not c then return false end
    return bit.band(ip_num, c.mask) == bit.band(c.subnet, c.mask)
end

--- Does `ip` fall inside ANY entry of `list`?
-- @param list table|nil: array of "a.b.c.d" or "a.b.c.d/nn" strings
function _M.match_any(ip, list)
    if type(list) ~= "table" then return false end
    local ip_num = parse_ipv4(ip)
    if not ip_num then return false end
    for _, entry in ipairs(list) do
        if type(entry) == "string" then
            if entry == ip then return true end
            local c = cidr_mask(entry)
            if c and bit.band(ip_num, c.mask) == bit.band(c.subnet, c.mask) then
                return true
            end
        end
    end
    return false
end

return _M
