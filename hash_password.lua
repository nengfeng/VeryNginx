#!/usr/bin/env luajit
-- Helper script to generate a password hash for VeryNginx config.json
-- Usage: luajit hash_password.lua <your-password>

local password_hash = require "core.password_hash"
local random = require "core.random"

ngx = {
    log = function() end,
    hmac_sha256 = function(secret, data)
        -- Use OpenSSL if available, otherwise require openssl
        local ok, hmac = pcall(require, "openssl.hmac")
        if ok then
            return hmac:new(secret, "sha256"):final(data)
        end
        error("openssl.hmac not available in CLI mode")
    end,
    encode_base64 = function(s)
        local ok, enc = pcall(require, "openssl.enc")
        if ok then
            return enc:encode_base64(s)
        end
        -- fallback: use base64 from lua
        return (s:gsub(".", function(c)
            return string.format("%02x", string.byte(c))
        end))
    end,
    decode_base64 = function(s) return s end,
}

local password = arg[1]
if not password or password == "" then
    io.stderr:write("Usage: luajit hash_password.lua <password>\n")
    os.exit(1)
end

local hash = password_hash.hash(password)
if hash then
    io.write(hash .. "\n")
else
    io.stderr:write("Failed to generate password hash\n")
    os.exit(1)
end
