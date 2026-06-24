-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : password hashing - bcrypt/argon2 with fallback rejection

local _M = {}

local hash_impl = nil

--- Detect available hashing implementation.
-- Priority: bcrypt > argon2 > reject startup
local function detect_impl()
    local ok_bcrypt, bcrypt = pcall(require, "bcrypt")
    if ok_bcrypt then
        ngx.log(ngx.WARN, "Using bcrypt for password hashing")
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
        ngx.log(ngx.WARN, "Using argon2 for password hashing")
        return {
            hash = function(password)
                return argon2.hash(password, { t = 2, m = 19456, p = 1 })
            end,
            verify = function(password, hash)
                return argon2.verify(hash, password)
            end
        }
    end

    ngx.log(ngx.ERR, "No password hashing library found. Install lua-resty-bcrypt or lua-resty-argon2")
    return nil
end

--- Hash a password.
-- @param password string: plaintext password
-- @return string|nil, string: encoded hash or error
function _M.hash(password)
    if not hash_impl then
        hash_impl = detect_impl()
    end
    if not hash_impl then
        return nil, "no hashing library available"
    end
    local ok, result = pcall(hash_impl.hash, password)
    if not ok then
        return nil, tostring(result)
    end
    return result
end

--- Verify a password against a stored hash.
-- @param password string: plaintext password to verify
-- @param encoded_hash string: stored hash
-- @return boolean
function _M.verify(password, encoded_hash)
    if not hash_impl then
        hash_impl = detect_impl()
    end
    if not hash_impl then
        ngx.log(ngx.ERR, "password_hash.verify called but no hashing library available")
        return false
    end
    local ok, result = pcall(hash_impl.verify, password, encoded_hash)
    if not ok then
        ngx.log(ngx.ERR, "password verification error: ", tostring(result))
        return false
    end
    return result
end

return _M