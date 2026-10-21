-- -*- coding: utf-8 -*-
-- @Disc    : live traffic shape — the dimensions the panel was missing
--
-- WHY THIS EXISTS
-- ---------------
-- The statistics engine counts requests per (bucket, host, uri) and records
-- the response code per entry. That answers "which paths are hot" and
-- "which rules fired". It cannot answer the questions that actually matter
-- while an attack is running:
--
--   * How many DIFFERENT clients are hitting us, and how many requests does
--     each one make? A normal forum is ~0.2 requests per client. A
--     distributed scraper that takes one request per IP and rotates its
--     address is 1.0+. The ratio is the single most diagnostic number in a
--     distributed attack, and it was not collected anywhere.
--   * What does the traffic LOOK LIKE — which user agents, which paths, does
--     it carry cookies, does it send a referer? A scraper that mirrors a
--     browser is indistinguishable from a browser request by path alone.
--   * What did the BACKEND return? The panel had no status-code rollup, and
--     the codes that matter during an overload (499 client gave up, 502
--     upstream failed, 429 rate limited) were not even in the recorded set.
--
-- All three were gathered by hand from the access log during the 2026-10
-- incident that this module was written for: 3,662 distinct IPs in five
-- minutes at 1.01 requests each, every request carrying a phpBB session id
-- in the query string, 99.4% of them ending in 499/502. The information was
-- in the log the whole time; it just was not in the shape the panel could
-- show.
--
-- DESIGN CONSTRAINTS
-- ------------------
-- Everything here is bounded. The statistics dict already taught us what
-- unbounded looks like: 9,848 keys and 7,272 namespaces, and a /dicts
-- response of 678 KB.
--
--   * IP diversity uses a fixed-size SAMPLE, not a set. 256 four-byte hashes
--     plus a cursor is 1,028 bytes per host per minute, and the sample is
--     written round-robin so it stays representative of the whole minute
--     rather than only its first 256 visitors.
--   * Fingerprints are keyed by a hash and the number of distinct shapes per
--     host-minute is capped, with the least-seen shape evicted.
--   * Minute keys carry a TTL, so old minutes disappear on their own and
--     there is no rollup to maintain.
--
-- The IP sample deliberately stores a hash of the address, not the address
-- itself: the panel needs a count, and a visitor's address is not something
-- to keep lying around in a diagnostic buffer.
--
-- Sampling note: the statistics engine samples 1 request in 10
-- (LOG_SAMPLE_RATE). Every number here is therefore a sample too, and is
-- reported as such. Sampling does not bias the diversity ratio: each
-- sampled request is an independent draw from the same population.

local _M = {}

local dict_guard = require "core.dict_guard"

-- Host-minute key prefix. Distinct from the "1m:"/"5m:" bucket namespace so
-- these never take part in the bucket rollup: they are a time series, and a
-- rollup would destroy the per-minute shape.
local PREFIX = "lm:"

-- How long a minute's worth of data stays readable. 15 minutes is enough for
-- a sparkline plus a "when did this start" question, and it caps the dict cost
-- at hosts x 15 minutes.
local MINUTE_TTL = 900

-- Sample geometry. 256 hashes of 4 bytes plus a 4-byte cursor.
local SAMPLE_SLOTS = 256
local SAMPLE_BYTES = SAMPLE_SLOTS * 4 + 4

-- Maximum distinct fingerprints kept per host-minute.
local MAX_SHAPES = 32

-- ---------------------------------------------------------------------------
-- Shape normalization
-- ---------------------------------------------------------------------------

--- Turn a user agent into a family shape.
-- Digit runs become "*", so Chrome/142.0.0.0 and Chrome/145.0.0.0 collapse into
-- one shape. That is deliberate: a scraper rotating its Chrome version shows
-- up as ONE shape with a large count, which is exactly the thing worth
-- noticing.
local function ua_shape(ua)
    if not ua or ua == "" then return "ua:none" end
    local s = ua:gsub("%d+", "*")
    if #s > 96 then s = s:sub(1, 96) end
    return "ua:" .. s
end

--- Turn a request into a path shape: path plus the NAMES of its query
-- parameters, values removed. search.php?search_id=unanswered and
-- search.php?search_id=active_topics are the same shape.
local function path_shape(uri, args)
    local path = uri or "/"
    local names = {}
    if args then
        for k in pairs(args) do names[#names + 1] = k end
    end
    if #names > 0 then
        table.sort(names)
        path = path .. "?" .. table.concat(names, ",") .. "=*"
    end
    if #path > 96 then path = path:sub(1, 96) end
    return "p:" .. path
end

--- Combine the parts into one bounded, hashable shape key.
local function shape_key(ua, uri, args, flags)
    local raw = table.concat({
        ua_shape(ua), path_shape(uri, args),
        flags.cookie and "c1" or "c0",
        flags.referer and "r1" or "r0",
    }, "|")
    -- djb2 over the shape, so the key stays short no matter how long the user
    -- agent is. The readable shape is kept alongside for display.
    --
    -- No bitwise operators: this is LuaJIT (5.1), where "~" is unary only, so
    -- the FNV-style "h ~ byte" that reads naturally is a SYNTAX ERROR there. A
    -- syntax error in a module loaded at init_by_lua aborts the whole nginx
    -- reload — nginx keeps the old workers and only records the error, so the
    -- change silently does not take effect.
    local h = 5381
    for i = 1, #raw do
        h = (h * 33 + raw:byte(i)) % 4294967296
    end
    return string.format("%08x", h), raw
end

-- ---------------------------------------------------------------------------
-- IP sample
-- ---------------------------------------------------------------------------

--- Append one client address to the minute's sample, round-robin.
-- The cursor makes the sample a sliding window over the minute instead of
-- "the first 256 visitors", so a burst late in the minute is represented.
local function sample_add(shared, key, ip)
    local cur = shared:get(key)
    if not cur or #cur ~= SAMPLE_BYTES then
        cur = string.rep("\0", SAMPLE_BYTES)
    end
    local h = ngx.crc32_long(ip or "")
    -- 4 bytes of the hash, stored big-endian
    local packed = string.char(
        math.floor(h / 16777216) % 256,
        math.floor(h / 65536) % 256,
        math.floor(h / 256) % 256,
        h % 256)
    local cursor = cur:byte(SAMPLE_BYTES) or 0
    local offset = cursor * 4 + 1
    cur = cur:sub(1, offset - 1) .. packed .. cur:sub(offset + 4)
    cursor = (cursor + 1) % SAMPLE_SLOTS
    cur = cur:sub(1, SAMPLE_BYTES - 1) .. string.char(cursor)
    dict_guard.set(shared, "stats.live", key, cur, MINUTE_TTL)
end

--- Count distinct hashes in a sample.
-- Collisions across 256 slots of 32 bits are vanishingly unlikely, and a
-- collision would undercount by one, which is the safe direction.
--
-- Unwritten slots are all zero and must not be counted: a fresh sample is
-- 1,028 zero bytes, and treating that as one address would report a distinct
-- client even when only one had been seen.
local function sample_distinct(sample)
    if not sample or #sample < 4 then return 0 end
    local seen = {}
    local n = 0
    for i = 1, #sample - 4, 4 do
        local v = sample:sub(i, i + 3)
        if v ~= "\0\0\0\0" and not seen[v] then
            seen[v] = true
            n = n + 1
        end
    end
    return n
end

-- ---------------------------------------------------------------------------
-- Shape list (a tiny set, written only when a shape is first seen)
-- ---------------------------------------------------------------------------

local function encode_list(set)
    local parts = {}
    for h in pairs(set) do parts[#parts + 1] = h end
    table.sort(parts)
    return table.concat(parts, ",")
end

local function read_list(shared, key)
    local set = {}
    local data = shared:get(key)
    if not data or data == "" then return set end
    for h in data:gmatch("[^,]+") do set[h] = true end
    return set
end

-- ---------------------------------------------------------------------------
-- Recording
-- ---------------------------------------------------------------------------

--- Record one request into the live shape.
-- @param ctx table: the request context
function _M.record(ctx)
    if not ctx then return end
    local shared = ngx.shared.statistics
    if not shared then return end

    local req = ctx.request or {}
    local host = req.host or "_"
    local minute = os.date("%Y%m%d%H%M")
    local base = PREFIX .. host .. ":" .. minute

    -- Enumerate the hosts of a minute so the reader can list them without a key
    -- scan. Written once per host per minute: the add() returns true only the
    -- first time, so the read-modify-write below is off the per-request path.
    if shared:add(base .. ":seen", 1, MINUTE_TTL) then
        local hkey = PREFIX .. "hosts:" .. minute
        local list = shared:get(hkey) or ""
        if not list:find(host, 1, true) then
            dict_guard.set(shared, "stats.live", hkey,
                list .. (list ~= "" and "," or "") .. host, MINUTE_TTL)
        end
    end

    -- value=1, init=0, ttl=MINUTE_TTL. Note that incr does not refresh the
    -- TTL of an existing key, so the key expires MINUTE_TTL after the minute
    -- began — which is the intended window.
    dict_guard.incr(shared, "stats.live", base .. ":req", 1, 0, MINUTE_TTL)

    local ip = req.remote_addr or "?"
    sample_add(shared, base .. ":ip", ip)

    -- Fingerprint. Keyed by a hash so the key stays short; the readable shape
    -- is written once, next to it, for the panel to display.
    local args = ctx.get_uri_args and ctx.get_uri_args(ctx) or nil
    local flags = {
        cookie = (ngx.var.http_cookie ~= nil and ngx.var.http_cookie ~= ""),
        referer = (ngx.var.http_referer ~= nil and ngx.var.http_referer ~= ""),
    }
    local hash, raw = shape_key(req.user_agent, req.uri, args, flags)
    local fkey = base .. ":fp:" .. hash
    dict_guard.incr(shared, "stats.live", fkey, 1, 0, MINUTE_TTL)
    -- A separate "seen" marker, because incr cannot report whether it
    -- created the key. add returns true only the first time.
    local is_new = shared:add(base .. ":fpnew:" .. hash, 1, MINUTE_TTL)
    if is_new then
        -- First sighting: record when it appeared and what it looks like, so
        -- the panel can say "new since 14:38" and show the shape.
        dict_guard.set(shared, "stats.live", base .. ":fn:" .. hash,
            os.time() .. "\0" .. raw, MINUTE_TTL)
        local shapes = read_list(shared, base .. ":fpl")
        shapes[hash] = true
        -- Keep the list bounded: beyond the cap, drop the shape whose own
        -- counter is smallest, so a long tail cannot grow the dict.
        local n = 0
        for _ in pairs(shapes) do n = n + 1 end
        if n > MAX_SHAPES then
            local worst, worst_count
            for h in pairs(shapes) do
                local c = tonumber(shared:get(base .. ":fp:" .. h) or 0) or 0
                if not worst_count or c < worst_count then
                    worst, worst_count = h, c
                end
            end
            if worst then
                shapes[worst] = nil
                shared:delete(base .. ":fp:" .. worst)
                shared:delete(base .. ":fn:" .. worst)
                shared:delete(base .. ":fpnew:" .. worst)
            end
        end
        dict_guard.set(shared, "stats.live", base .. ":fpl",
            encode_list(shapes), MINUTE_TTL)
    end
end

-- ---------------------------------------------------------------------------
-- Reading
-- ---------------------------------------------------------------------------

--- Per-minute series for one host, oldest first.
-- @param host string
-- @param minutes number: how many minutes back to include
function _M.host_series(host, minutes)
    local shared = ngx.shared.statistics
    minutes = minutes or 10
    if not shared then return {} end
    local out = {}
    local now = os.time()
    for i = minutes - 1, 0, -1 do
        local t = now - i * 60
        local minute = os.date("%Y%m%d%H%M", t)
        local base = PREFIX .. host .. ":" .. minute
        local req = tonumber(shared:get(base .. ":req") or 0) or 0
        local ips = sample_distinct(shared:get(base .. ":ip"))
        local shapes = {}
        for h in pairs(read_list(shared, base .. ":fpl")) do
            local c = tonumber(shared:get(base .. ":fp:" .. h) or 0) or 0
            local meta = shared:get(base .. ":fn:" .. h) or ""
            local first_seen, raw = meta:match("^(%d+)%z(.*)$")
            shapes[#shapes + 1] = {
                hash = h, count = c,
                first_seen = tonumber(first_seen) or nil,
                shape = raw,
            }
        end
        table.sort(shapes, function(a, b) return a.count > b.count end)
        out[#out + 1] = {
            minute = os.date("%H:%M", t),
            ts = t,
            requests = req,
            distinct_ips = ips,
            -- Sampled requests per distinct client. Below ~0.5 reads as
            -- "one request per client" — the distributed-scraper signature.
            req_per_ip = (ips > 0) and (req / ips) or nil,
            -- True when the sample filled up, so the distinct count is a
            -- lower bound rather than an estimate.
            sample_full = (ips >= SAMPLE_SLOTS),
            shapes = shapes,
        }
    end
    return out
end

--- Every host that has live data in the recent window.
-- Enumerated from the per-minute host lists this module maintains, so it
-- reflects traffic that actually happened rather than every host the
-- statistics engine has ever seen.
function _M.hosts(minutes)
    local shared = ngx.shared.statistics
    if not shared then return {} end
    local seen = {}
    local out = {}
    local now = os.time()
    for i = 0, (minutes or 10) - 1 do
        local minute = os.date("%Y%m%d%H%M", now - i * 60)
        local list = shared:get(PREFIX .. "hosts:" .. minute)
        if list and list ~= "" then
            for h in list:gmatch("[^,]+") do
                if not seen[h] then
                    seen[h] = true
                    out[#out + 1] = h
                end
            end
        end
    end
    return out
end

return _M
