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

-- XOR implementation compatible with Lua 5.1 / 5.2 / LuaJIT.
local xor
do
    local ok, bitmod = pcall(require, "bit")
    if ok and type(bitmod) == "table" and type(bitmod.bxor) == "function" then
        xor = bitmod.bxor
    else
        -- Pure arithmetic XOR for environments without a usable bit library.
        xor = function(a, b)
            local r, p = 0, 1
            a = math.floor(a)
            b = math.floor(b)
            while a > 0 or b > 0 do
                if (a % 2) ~= (b % 2) then r = r + p end
                a = math.floor(a / 2)
                b = math.floor(b / 2)
                p = p * 2
            end
            return r
        end
    end
end

--- Seed the legacy math.random PRNG.
-- @param force boolean|nil: re-seed even when already seeded. Required in
--   init_worker: the module-load seed runs once in init_by_lua and every
--   forked worker inherits the IDENTICAL PRNG state (worker_id is still 0
--   there), so each worker must force a re-seed with its own PID/worker_id.
local function seed_prng(force)
    if seeded and not force then return end
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
    local seed = xor(xor(s1, s2), s3)
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

-- Seed the legacy math.random PRNG at module load time (init_by_lua context,
-- where ngx is available). Without this, any direct math.random() call
-- (statistics sampling, balancer jitter, snapshot jitter, etc.) produces an
-- identical sequence in every worker on every restart. seed_prng() is a no-op
-- once already seeded, so calling it here is cheap and idempotent.
-- NOTE: this alone is NOT worker-safe — init_by_lua runs once in the master
-- and workers fork with identical PRNG state. core/init.lua's init_worker
-- calls _M.seed(true) per worker to re-seed with the real PID/worker_id.
if ngx ~= nil then
    seed_prng()
end

_M.seed = seed_prng

return _M