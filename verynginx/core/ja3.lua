-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : TLS/JA3 fingerprint extraction for improved client identification

local _M = {}

-- Try to read JA3 hash from nginx variable (requires nginx-module-vt or
-- OpenResty with JA3 support compiled in). Returns nil if unavailable.
function _M.get_ja3()
    if ngx.var.ssl_client_j3_hash and ngx.var.ssl_client_j3_hash ~= "" then
        return ngx.var.ssl_client_j3_hash
    end
    return nil
end

-- Try to read JA3 TLS fingerprint text (human-readable breakdown)
function _M.get_ja3_text()
    if ngx.var.ssl_client_ja3_text and ngx.var.ssl_client_ja3_text ~= "" then
        return ngx.var.ssl_client_ja3_text
    end
    return nil
end

-- Get a simplified TLS fingerprint from available SSL variables.
-- This is NOT a real JA3 (which requires raw Client Hello), but provides
-- a useful identifier based on available SSL parameters.
function _M.get_simple_fingerprint()
    local parts = {}
    local ssl_protocol = ngx.var.ssl_protocol or ""
    local ssl_cipher = ngx.var.ssl_cipher or ""
    local ssl_client_s_dn = ngx.var.ssl_client_s_dn or ""

    if ssl_protocol ~= "" then parts[#parts + 1] = ssl_protocol end
    if ssl_cipher ~= "" then parts[#parts + 1] = ssl_cipher end
    if ssl_client_s_dn ~= "" then parts[#parts + 1] = ngx.md5(ssl_client_s_dn):sub(1, 8) end

    if #parts == 0 then
        return nil
    end
    return table.concat(parts, "|")
end

-- Get the best available fingerprint: JA3 > simple fingerprint > nil
function _M.get_fingerprint()
    local ja3 = _M.get_ja3()
    if ja3 then return "ja3:" .. ja3 end
    local fp = _M.get_simple_fingerprint()
    if fp then return "tls:" .. fp end
    return nil
end

return _M
