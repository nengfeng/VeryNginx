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
        local ok, mime = pcall(require, "mime")
        if ok then
            return mime.b64(s)
        end
        -- inline base64 fallback
        local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        local r = {}
        local i = 1
        while i <= #s do
            local a = string.byte(s, i)
            local b1 = string.byte(s, i + 1) or 0
            local c = string.byte(s, i + 2) or 0
            local left = #s - i + 1
            r[#r + 1] = b:sub(math.floor(a / 4) + 1, math.floor(a / 4) + 1)
            r[#r + 1] = b:sub((a % 4) * 16 + math.floor(b1 / 16) + 1, (a % 4) * 16 + math.floor(b1 / 16) + 1)
            if left == 1 then
                r[#r + 1] = '='
                r[#r + 1] = '='
            elseif left == 2 then
                r[#r + 1] = b:sub((b1 % 16) * 4 + 1, (b1 % 16) * 4 + 1)
                r[#r + 1] = '='
            else
                r[#r + 1] = b:sub((b1 % 16) * 4 + math.floor(c / 64) + 1, (b1 % 16) * 4 + math.floor(c / 64) + 1)
                r[#r + 1] = b:sub(c % 64 + 1, c % 64 + 1)
            end
            i = i + 3
        end
        return table.concat(r)
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
