-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking IP encoding utilities + v2 key builder.
--             v2 contract: limiter.build_key() returns dimension-only,
--             caller assembles full namespace.
--
--   Count key:  fl:v2:count:<enc_rule_id>:<enc_dimension>
--   CC evidence: fl:v2:kernel:violation:<enc_rule_id>:<ip>:<slot>

local _M = {}

-- Length-prefix encoding: prevents colon-collision when raw values contain ':'.
-- Format: <1-byte length><bytes>
-- e.g. "ip" => "\x02ip", "192.168.1.1" => "\x0b192.168.1.1"
local function len_prefix(val)
    local s = tostring(val)
    local len = #s
    if len > 255 then
        -- For very long values, use a 2-byte length prefix
        local hi = math.floor(len / 256)
        local lo = len % 256
        return string.char(255, hi, lo) .. s
    end
    return string.char(len) .. s
end

-- Normalize an IPv4 address: strip leading zeros.
local function normalize_ipv4(ip)
    if not ip then return "unknown" end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return ip end
    return string.format("%d.%d.%d.%d", tonumber(a), tonumber(b), tonumber(c), tonumber(d))
end

-- Normalize an IPv6 address: lowercase, full expansion then compression.
-- For our purposes, lowercase + strip leading zeros in each group is enough.
local function normalize_ipv6(ip)
    if not ip then return "unknown" end
    ip = ip:lower()
    -- Replace longest run of ":0:0:..." with "::"
    -- Simple approach: return lowercase
    return ip
end

function _M.canonical_ip(ip)
    if not ip then return "unknown" end
    if ip:match("^%d+%.%d+%.%d+%.%d+$") then
        return normalize_ipv4(ip)
    end
    return normalize_ipv6(ip)
end

-- Encode a rule ID for key usage.
function _M.encode_rule_id(rule_id)
    return len_prefix(rule_id)
end

-- Encode a dimension value for key usage.
function _M.encode_dimension(dim)
    return len_prefix(dim)
end

-- Build v2 counter storage key.
-- @param rule_id string: stable frequency rule ID (from migration)
-- @param dim_enc string: encoded dimension value (from limiter.build_key v2)
-- @return string: full shared-dict key
function _M.v2_count_key(rule_id, dim_enc)
    return "fl:v2:count:" .. rule_id .. ":" .. dim_enc
end

-- Build v2 CC violation evidence key.
-- @param rule_id string: stable frequency rule ID
-- @param ip string: canonical IP
-- @param slot number: evidence_slot = floor(time / rule.window)
-- @return string: full shared-dict key
function _M.v2_violation_key(rule_id, ip, slot)
    return "fl:v2:kernel:violation:" .. rule_id .. ":" .. ip .. ":" .. tostring(slot)
end

return _M
