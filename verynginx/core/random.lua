-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : secure random number generation

local _M = {}

local seeded = false

local function get_pid()
    -- Try reading from /proc first (nginx worker pid).
    local f = io.open("/proc/self/stat", "r")
    if f then
        local line = f:read("*l")
        f:close()
        if line then
            local pid = tonumber(line:match("^(%d+)"))
            if pid then return pid end
        end
    end
    return 0
end

local function seed_prng()
    if seeded then return end
    seeded = true
    -- Gather entropy from multiple time/worker sources.
    local worker_id = (ngx and ngx.worker and ngx.worker.id) and ngx.worker.id() or 0
    local pid = get_pid()
    -- Prefer ngx.now (wall-clock microseconds in request context) over os.time.
    local t = (ngx and ngx.now) and ngx.now() or (os.clock() + os.time())
    local clock = os.clock() or 0
    -- PID + microsecond time + worker id + clock jitter (mixed via XOR).
    local s1 = math.floor(t * 1000000)
    local s2 = math.floor(clock * 1000000000)
    local s3 = pid * 7919 + worker_id * 104729
    local seed = s1 ~ s2 ~ s3
    -- Ensure positive seed (math.randomseed may truncate negatives).
    if seed < 0 then seed = -seed end
    math.randomseed(seed)
    -- Warm up to flush poor initial values.
    for _ = 1, 10 do math.random() end
end

--- Generate N random bytes as a binary string.
-- Uses OpenResty's ngx.random_bytes if available, then /dev/urandom.
-- Seeds math.random with entropy from time+pid+worker before fallback use.
function _M.bytes(length)
    length = length or 16
    local ok, result = pcall(ngx.random_bytes, length)
    if ok and result then
        return result
    end
    -- fallback: read from /dev/urandom (available on all Linux systems)
    local f = io.open("/dev/urandom", "rb")
    if f then
        local data = f:read(length)
        f:close()
        if data and #data == length then
            return data
        end
    end
    -- Last resort: seed prng before use to avoid predictable sequences.
    seed_prng()
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