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

-- Normalize an IPv6 address per RFC 5952: expand to 8 groups, compress
-- longest zero run, lowercase. Handles IPv4-mapped IPv6 (::ffff:x.x.x.x)
-- by converting to pure IPv4 when possible.
local function normalize_ipv6(ip)
    if not ip then return "unknown" end
    ip = ip:lower()

    -- Strip zone identifier (e.g., "%eth0")
    ip = ip:gsub("%%.*$", "")

    -- Handle IPv4-mapped IPv6: ::ffff:a.b.c.d => normalized IPv4
    local ipv4 = ip:match("^::ffff:(%d+%.%d+%.%d+%.%d+)$")
    if ipv4 then return normalize_ipv4(ipv4) end

    -- Expand :: to full 8-group form.
    local prefix, suffix = ip:match("^(.*)::(.*)$")
    if prefix then
        local head = prefix ~= "" and prefix or ""
        local tail = suffix ~= "" and suffix or ""
        local head_parts = {}
        for p in head:gmatch("[^:]+") do head_parts[#head_parts + 1] = p end
        local tail_parts = {}
        for p in tail:gmatch("[^:]+") do tail_parts[#tail_parts + 1] = p end
        local missing = 8 - #head_parts - #tail_parts
        local groups = {}
        for _, p in ipairs(head_parts) do groups[#groups + 1] = p end
        for _ = 1, missing do groups[#groups + 1] = "0" end
        for _, p in ipairs(tail_parts) do groups[#groups + 1] = p end
        ip = table.concat(groups, ":")
    end

    -- Parse and zero-pad each group to 4 hex digits, track longest zero run.
    local groups = {}
    for part in ip:gmatch("[^:]+") do
        -- Pad with leading zeros to 4 digits
        groups[#groups + 1] = string.rep("0", 4 - #part) .. part
    end

    -- Helper: strip leading zeros (RFC 5952 §4.1): 0000 -> "0", 0001 -> "1".
    local function strip(g)
        local s = g:gsub("^0+", "")
        return s == "" and "0" or s
    end

    -- RFC 5952: compress the longest run of all-zero groups with "::".
    -- If tied, compress the leftmost.
    local best_start, best_len = 0, 0
    local cur_start, cur_len = 0, 0
    for i, g in ipairs(groups) do
        if g == "0000" then
            if cur_len == 0 then cur_start = i end
            cur_len = cur_len + 1
            if cur_len > best_len then
                best_start = cur_start
                best_len = cur_len
            end
        else
            cur_len = 0
        end
    end

    -- Build result: replace longest zero run with "::" (or ":" edges).
    if best_len >= 2 then
        local before = {}
        for i = 1, best_start - 1 do before[#before + 1] = strip(groups[i]) end
        local after = {}
        for i = best_start + best_len, #groups do after[#after + 1] = strip(groups[i]) end
        if #before == 0 and #after == 0 then
            return "::"
        elseif #before == 0 then
            return "::" .. table.concat(after, ":")
        elseif #after == 0 then
            return table.concat(before, ":") .. "::"
        else
            return table.concat(before, ":") .. "::" .. table.concat(after, ":")
        end
    end

    -- No compressible run (single 0000 groups become "0").
    local out = {}
    for _, g in ipairs(groups) do
        out[#out + 1] = strip(g)
    end
    return table.concat(out, ":")
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
