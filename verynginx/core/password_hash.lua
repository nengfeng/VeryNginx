-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : password hashing - PBKDF2-HMAC-SHA256 built-in, bcrypt/argon2 optional upgrade

local _M = {}
local random = require "core.random"

local DEFAULT_ITERATIONS = 12000
local SALT_BYTES = 16

--- PBKDF2-HMAC-SHA256 (single block, dkLen <= 32).
-- Built-in implementation using ngx.hmac_sha256, no external dependencies.
-- Format: "p1$iterations$salt_b64$hash_b64"
local function pbkdf2_hmac_sha256(password, salt, iterations)
    local u = ngx.hmac_sha256(password, salt .. "\0\0\0\1")
    local result = u
    for i = 2, iterations do
        u = ngx.hmac_sha256(password, u)
        local xored = {}
        for j = 1, 32 do
            xored[j] = string.char(string.byte(result, j) ~ string.byte(u, j))
        end
        result = table.concat(xored)
    end
    return result
end

local function hash_builtin(password)
    local salt = random.bytes(SALT_BYTES)
    local derived = pbkdf2_hmac_sha256(password, salt, DEFAULT_ITERATIONS)
    return string.format("p1$%d$%s$%s",
        DEFAULT_ITERATIONS,
        ngx.encode_base64(salt),
        ngx.encode_base64(derived))
end

local function verify_builtin(password, encoded)
    local algo, iter_str, salt_b64, hash_b64 = encoded:match("^(%w+)%$(%d+)%$(.+)%$(.+)$")
    if algo ~= "p1" then
        return false
    end
    local iterations = tonumber(iter_str)
    local salt = ngx.decode_base64(salt_b64)
    if not salt then
        return false
    end
    local derived = pbkdf2_hmac_sha256(password, salt, iterations)
    return ngx.encode_base64(derived) == hash_b64
end

--- External library detection: bcrypt > argon2
local function detect_external()
    local ok_bcrypt, bcrypt = pcall(require, "bcrypt")
    if ok_bcrypt then
        return {
            hash = function(password)
                return bcrypt.digest(password, bcrypt.gen_salt(12))
            end,
            verify = function(password, hash)
                return bcrypt.verify(password, hash)
            end
        }
    end

    local ok_argon2, argon2 = pcall(require, "argon2")
    if ok_argon2 then
        return {
            hash = function(password)
                return argon2.hash(password, { t = 2, m = 19456, p = 1 })
            end,
            verify = function(password, hash)
                return argon2.verify(hash, password)
            end
        }
    end

    return nil
end

local external_impl = nil
local external_tested = false

--- Hash a password using the best available method.
-- Returns a string that embeds algorithm info for verification.
function _M.hash(password)
    if not external_tested then
        external_impl = detect_external()
        external_tested = true
    end
    if external_impl then
        local ok, result = pcall(external_impl.hash, password)
        if ok and result then
            return result
        end
    end
    return hash_builtin(password)
end

--- Verify a password against a stored hash.
-- Auto-detects format: p1$=builtin, otherwise tries external libraries.
function _M.verify(password, encoded)
    if not encoded or encoded == "" then
        return false
    end

    -- Detect built-in format
    if encoded:sub(1, 2) == "p1" then
        return verify_builtin(password, encoded)
    end

    -- For bcrypt/argon2 format, try external libraries
    if not external_tested then
        external_impl = detect_external()
        external_tested = true
    end
    if external_impl then
        local ok, result = pcall(external_impl.verify, password, encoded)
        if ok and result then
            return true
        end
    end
    return false
end

return _M
