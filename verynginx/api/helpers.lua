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
    -- IPv4-mapped IPv6 literal (::ffff:a.b.c.d): validate the embedded v4.
    -- Case-insensitive per RFC 5952 §4 hex normalization.
    local mapped = ip:lower():match("^::ffff:(%d+%.%d+%.%d+%.%d+)$")
    if mapped then ip = mapped end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if a then
        return tonumber(a) <= 255 and tonumber(b) <= 255
            and tonumber(c) <= 255 and tonumber(d) <= 255
    end
    return is_valid_ipv6(ip)
end

--- Parse a rate-limit spec from config.security.rate_limit ("30/m").
-- @param spec string|nil: "<count>/<s|m|h>"
-- @return limit number, window seconds — or nil when unparsable
function _M.parse_rate_limit(spec)
    if type(spec) ~= "string" then return nil end
    local n, unit = spec:match("^(%d+)%s*/%s*([smh])$")
    if not n then return nil end
    local window = unit == "s" and 1 or (unit == "m" and 60 or 3600)
    return tonumber(n), window
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

--- Normalise an ETag value to the bare opaque token used by
--- core.config.current_hash(). Clients may send the quoted form ("abc")
--- and proxies may prefix a weak comparator (W/"abc"); both are valid HTTP
--- grammar, neither should be compared literally against the stored hash.
function _M.normalize_etag(value)
    if type(value) ~= "string" or value == "" then
        return nil
    end
    value = value:gsub("^%s+", ""):gsub("%s+$", "")
    if value:sub(1, 2) == "W/" then
        value = value:sub(3)
    end
    if #value >= 2 and value:sub(1, 1) == '"' and value:sub(-1) == '"' then
        value = value:sub(2, -2)
    end
    return value ~= "" and value or nil
end

--- Hash of the config the client last read, sent back with a full-config
--- write so a stale save can be refused (409) instead of silently reverting
--- a concurrent edit.
--
-- The value travels in `X-Config-Hash`, NOT the standard `If-Match`
-- request header. On this nginx (1.30.7) the not-modified response filter
-- (ngx_http_not_modified_header_filter, built in) evaluates a specific
-- If-Match value against the RESPONSE ETag, but only for 200 answers:
-- non-200 responses (401/409) pass through, and `If-Match: *` always
-- passes. A 200 whose ETag does not match — or which has NO ETag — is
-- turned into a 412 by the filter, and the filter runs after the Lua
-- content phase, so the handler has already done its work. The fatal case
-- for P1-5: POST /config's success reply is a 200 with no ETag (only
-- GET /config sets one), so even a correct If-Match save would come back
-- 412 to the client. (Verified against the nginx 1.30.7 source and with
-- minimal configs on this host.)
-- `X-Config-Hash` is a custom header nginx does not evaluate, so it
-- reaches the controller intact. The standard `If-Match` is still
-- accepted as a fallback for servers whose responses do not pass through
-- that filter with these header shapes.
--
-- Request header keys: lua-nginx-module lower-cases header names in
-- ngx.req.get_headers() (verified on the deployed nginx 1.30.7 +
-- lua-nginx-module 0.10.32rc8), so look the keys up in lower case.
function _M.requested_config_version()
    local headers = ngx.req.get_headers()
    local raw = headers["x-config-hash"]
    if type(raw) == "string" and raw ~= "" then
        -- Accept both the bare form and a client echoing the ETag verbatim.
        return _M.normalize_etag(raw)
    end
    return _M.normalize_etag(headers["if-match"])
end

--- Redact GeoIP credential fields on a geoip config section (in place).
--
-- GET /config, GET /config/export and GET /geoip/config all must hide live
-- keys; a single list here keeps the three call sites from drifting apart.
-- Non-empty values are replaced with the same "(redacted)" sentinel that
-- core.config.save() backfills (the established contract for admin
-- password_hash and security session_secret), so a dashboard read-modify-save
-- cycle that leaves a box untouched preserves the real key.
local GEOIP_CREDENTIAL_FIELDS = { "license_key", "abuseipdb_key", "ipinfo_token" }

function _M.redact_geoip_credentials(section)
    if type(section) ~= "table" then return end
    for _, k in ipairs(GEOIP_CREDENTIAL_FIELDS) do
        if type(section[k]) == "string" and section[k] ~= "" then
            section[k] = "(redacted)"
        end
    end
end

return _M
