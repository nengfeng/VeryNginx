-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : HMAC session token - sign, verify, expire, key rotation

local _M = {}
local hmac = require "core.hmac"

-- Constant-time string comparison to prevent timing side-channel attacks.
-- Uses arithmetic (a+b)*(a-b) = a^2 - b^2 instead of short-circuit string comparison.
local function constant_time_compare(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then
        return false
    end
    if #a ~= #b then
        return false
    end
    local result = 0
    for i = 1, #a do
        local ab, bb = a:byte(i), b:byte(i)
        result = result + (ab + bb) * (ab - bb)
    end
    return result == 0
end

-- Exposed for unit testing
_M._constant_time_compare = constant_time_compare

--- Sign a payload into a session token using HMAC-SHA256.
-- @param payload table: { user, expire_at, nonce }
-- @param secret string: HMAC signing key
-- @return string: base64-encoded token
function _M.sign(payload, secret)
    if not payload or not secret then
        return nil, "payload and secret required"
    end
    local json = require "dkjson"
    local data = json.encode(payload)
    local sig = hmac.hmac_sha256(secret, data)
    local token = ngx.encode_base64(data) .. "." .. ngx.encode_base64(sig)
    return token
end

--- Verify a session token and return the decoded payload.
-- @param token string: base64-encoded token from sign()
-- @param secret string: HMAC signing key
-- @return boolean ok, table|string payload_or_error
function _M.verify(token, secret)
    if not token or not secret then
        return false, "token and secret required"
    end

    local dot_pos = token:find("%.")
    if not dot_pos then
        return false, "invalid token format"
    end

    local data_b64 = token:sub(1, dot_pos - 1)
    local sig_b64 = token:sub(dot_pos + 1)

    local data = ngx.decode_base64(data_b64)
    if not data then
        return false, "invalid token encoding"
    end

    -- Verify signature
    local expected_sig = hmac.hmac_sha256(secret, data)
    local actual_sig = ngx.decode_base64(sig_b64)
    if not actual_sig or not constant_time_compare(expected_sig, actual_sig) then
        return false, "invalid signature"
    end

    -- Decode payload (with pcall to catch malformed JSON)
    local json = require "dkjson"
    local ok, payload = pcall(json.decode, data)
    if not ok or not payload then
        return false, "invalid payload"
    end

    -- Check expiration
    if payload.expire_at and payload.expire_at < ngx.time() then
        return false, "token expired"
    end

    return true, payload
end

--- Verify with key rotation support (accepts list of secrets).
-- @param token string: the session token
-- @param secrets table: ordered list of { secret, version } entries
-- @return boolean ok, table|string payload_or_error
function _M.verify_with_rotation(token, secrets)
    if not token or not secrets or #secrets == 0 then
        return false, "token and secrets required"
    end
    for _, entry in ipairs(secrets) do
        local ok, result = _M.verify(token, entry.secret)
        if ok then
            return true, result
        end
    end
    return false, "no matching secret"
end

return _M