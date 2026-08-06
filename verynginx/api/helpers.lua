-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : shared helpers for API controllers

local _M = {}

local json = require "dkjson"

--- Strict IPv6 format check: 8 groups (or fewer with a single `::`),
--- each group 1-4 lowercase/uppercase hex digits, no embedded whitespace.
local function is_valid_ipv6(ip)
    if type(ip) ~= "string" or ip == "" then return false end
    if ip:find("%s") then return false end
    if ip:find("%z") then return false end
    -- reject three or more consecutive colons (e.g. ":::")
    if ip:find(":::", 1, true) then return false end
    -- reject a leading/trailing single colon that is not part of `::`
    if ip:sub(1, 1) == ":" and ip:sub(1, 2) ~= "::" then return false end
    if ip:sub(-1) == ":" and ip:sub(-2) ~= "::" then return false end
    local dbl = 0
    for _ in ip:gmatch("::") do dbl = dbl + 1 end
    if dbl > 1 then return false end
    if not ip:match("%x") then return false end
    local ngroups = 0
    for part in ip:gmatch("[^:]+") do
        ngroups = ngroups + 1
        if not part:match("^%x+$") or #part > 4 then return false end
    end
    if dbl == 1 then
        return ngroups <= 7
    end
    return ngroups == 8
end

--- Unified IP format validation across API controllers.
--- Accepts a well-formed IPv4 (four octets 0-255) or IPv6 address.
function _M.is_valid_ip(ip)
    if type(ip) ~= "string" or ip == "" then return false end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if a then
        return tonumber(a) <= 255 and tonumber(b) <= 255
            and tonumber(c) <= 255 and tonumber(d) <= 255
    end
    return is_valid_ipv6(ip)
end

--- Read request args from a JSON body or fall back to POST form args.
function _M.get_request_args()
    ngx.req.read_body()
    local content_type = ngx.var.content_type or ""
    if content_type:lower():find("application/json", 1, true) then
        local body = ngx.req.get_body_data()
        if body and body ~= "" then
            local ok, parsed = pcall(json.decode, body)
            if ok then return parsed end
        end
    end
    return ngx.req.get_post_args()
end

return _M
