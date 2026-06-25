-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : secure random number generation

local _M = {}

--- Generate N random bytes as a binary string.
-- Uses OpenResty's ngx.random_bytes if available, otherwise os.time() fallback.
function _M.bytes(length)
    length = length or 16
    local ok, result = pcall(ngx.random_bytes, length)
    if ok and result then
        return result
    end
    -- fallback: not cryptographically secure, only used when ngx is unavailable
    local buf = {}
    for i = 1, length do
        buf[i] = string.char(math.random(0, 255))
    end
    return table.concat(buf)
end

--- Generate N random bytes as a hex string.
function _M.hex(length)
    local raw = _M.bytes(length)
    local hex = ""
    for i = 1, #raw do
        hex = hex .. string.format("%02x", string.byte(raw, i))
    end
    return hex
end

return _M