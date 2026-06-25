-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : password hashing - PBKDF2-HMAC-SHA256 built-in, bcrypt/argon2 optional upgrade

local _M = {}
local random = require "core.random"

local bxor
do
    local ok, bitmod = pcall(require, "bit")
    if ok then
        bxor = bitmod.bxor
    else
        function bxor(a, b)
            local r, p = 0, 1
            while a > 0 or b > 0 do
                if a % 2 ~= b % 2 then r = r + p end
                a, b, p = math.floor(a / 2), math.floor(b / 2), p * 2
            end
            return r
        end
    end
end

local DEFAULT_ITERATIONS = 12000
local SALT_BYTES = 16

local hmac_sha256
do
    if ngx.hmac_sha256 then
        hmac_sha256 = ngx.hmac_sha256
    else
        local ok, ffi = pcall(require, "ffi")
        if ok then
            ffi.cdef[[
                const void *EVP_sha256(void);
                unsigned char *HMAC(const void *evp_md, const void *key, int key_len,
                                    const unsigned char *data, int data_len,
                                    unsigned char *md, unsigned int *md_len);
            ]]
            local C = ffi.C
            local evp_sha256 = C.EVP_sha256
            local hmac = C.HMAC
            hmac_sha256 = function(key, data)
                local md = ffi.new("unsigned char[32]")
                local md_len = ffi.new("unsigned int[1]")
                local ret = hmac(evp_sha256(), key, #key, data, #data, md, md_len)
                if not ret then
                    return nil
                end
                return ffi.string(md, 32)
            end
        else
            ngx.log(ngx.WARN, "password_hash: no HMAC-SHA256 implementation available")
            hmac_sha256 = function() return nil end
        end
    end
end

--- PBKDF2-HMAC-SHA256 (single block, dkLen <= 32).
-- Built-in implementation using ngx.hmac_sha256, no external dependencies.
-- Format: "p1$iterations$salt_b64$hash_b64"
local function pbkdf2_hmac_sha256(password, salt, iterations)
    local u = hmac_sha256(password, salt .. "\0\0\0\1")
    if not u then
        ngx.log(ngx.ERR, "password_hash: pbkdf2 first hmac failed")
        return nil
    end
    local result = u
    for i = 2, iterations do
        u = hmac_sha256(password, u)
        if not u then
            ngx.log(ngx.ERR, "password_hash: pbkdf2 hmac iteration ", i, " failed")
            return nil
        end
        local xored = {}
        for j = 1, 32 do
            xored[j] = string.char(bxor(string.byte(result, j), string.byte(u, j)))
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
    if not derived then
        return false
    end
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
