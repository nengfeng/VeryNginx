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
local hostname = require "core.hostname"

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

-- Maximum distinct hosts kept in the per-minute list. A rotating or spoofed
-- Host header must not be able to fill the 20 MB statistics dict with `lm:`
-- namespaces; 256 is far above any real deployment's vhost count.
local MAX_HOSTS_PER_MINUTE = 256

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
    -- The same normalization the statistics engine and the frequency limiter
    -- use: a raw Host header can carry ":"/"," (key and list separators) and
    -- has no length bound, so using it verbatim would let one request invent
    -- dict namespaces and forge host-list entries.
    local host = hostname.normalize(req.host)
    local minute = os.date("%Y%m%d%H%M", ngx.time())
    local base = PREFIX .. host .. ":" .. minute

    -- Enumerate the hosts of a minute so the reader can list them without a key
    -- scan, and bound the per-minute cardinality. Membership is delimiter-aware:
    -- a plain substring test treats "example.com" as already present when
    -- "www.example.com" was recorded first, and the shorter host then never
    -- appears in hosts().
    local hkey = PREFIX .. "hosts:" .. minute
    local list = shared:get(hkey) or ""
    if not ("," .. list .. ","):find("," .. host .. ",", 1, true) then
        local n = 0
        if list ~= "" then n = select(2, list:gsub(",", "")) + 1 end
        if n >= MAX_HOSTS_PER_MINUTE then
            -- Over the cap: create no per-host keys for this minute.
            return
        end
        -- Elect one writer so two workers cannot clobber each other's append.
        -- add() returns true only for the first request of this host/minute,
        -- so the read-modify-write below is off the per-request path.
        if shared:add(base .. ":seen", 1, MINUTE_TTL) then
            local cur = shared:get(hkey) or ""
            if not ("," .. cur .. ","):find("," .. host .. ",", 1, true) then
                dict_guard.set(shared, "stats.live", hkey,
                    cur .. (cur ~= "" and "," or "") .. host, MINUTE_TTL)
            end
        end
    end

    -- value=1, init=0, ttl=MINUTE_TTL. Note that incr does not refresh the
    -- TTL of an existing key, so the key expires MINUTE_TTL after the minute
    -- began — which is the intended window.
    dict_guard.incr(shared, "stats.live", base .. ":req", 1, 0, MINUTE_TTL)

    -- Failures, counted here rather than read back from the statistics engine:
    -- the history rollup runs on a timer and needs the number for the minute
    -- it is folding, and the 1m bucket is flushed away under it.
    --
    -- Narrow on purpose — see _M.is_backend_failure. 403 is the WAF blocking
    -- and 429 is the rate limiter working; neither is a backend failure, and
    -- counting them here would make the history show a site in trouble
    -- precisely when the defence is doing its job.
    local status = tonumber(ngx.var.status) or 0
    if _M.is_backend_failure(status) then
        dict_guard.incr(shared, "stats.live", base .. ":fail", 1, 0, MINUTE_TTL)
    end

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
            ngx.time() .. "\0" .. raw, MINUTE_TTL)
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
    local now = ngx.time()
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
    local now = ngx.time()
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

-- ---------------------------------------------------------------------------
-- History and baselines
-- ---------------------------------------------------------------------------
--
-- The live minute data above lives for 15 minutes, which is enough for a
-- sparkline but not for a baseline. A number without a baseline is not an
-- alarm: "74%" means nothing until you know what this host normally does.
--
-- History is kept as ONE KEY PER HOST, holding a text series of
-- "minute,requests,distinct_clients,failures" records separated by ";":
--
--   hist:<host>    the last 180 minutes
--   histH:<host>   the last 168 hours
--
-- One key per host rather than one per host per minute, and that matters
-- twice over. The statistics dict already answers /dicts with 678 KB because
-- it held 7,272 namespaces; a per-minute key layout would have added about a
-- thousand more. And a NEW shared dict would have needed a full nginx
-- restart — shared-memory zones are created by the master, not by a reload —
-- which on a live box means clearing the rate-limit counters, the reputation
-- data and the statistics at once. Twelve keys need no restart and add
-- nothing measurable to the dictionary listing.
--
-- The hour row keeps the MAX distinct clients seen in any minute of the hour
-- rather than a sum: summing distinct counts over minutes counts the same
-- person repeatedly, and a union of the samples is not available.

local HIST_MINUTES = 180
local HIST_HOURS = 168

-- Kept in the statistics dict rather than in a dedicated one, for the reason
-- above. A separate zone would need a master restart to exist.
local function hist_dict()
    return ngx.shared.statistics
end

local function encode_records(records)
    local parts = {}
    for _, r in ipairs(records) do
        parts[#parts + 1] = table.concat({ r.ts, r.requests, r.distinct_ips, r.fails }, ",")
    end
    return table.concat(parts, ";")
end

local function decode_records(raw)
    local out = {}
    if not raw or raw == "" then return out end
    for rec in raw:gmatch("[^;]+") do
        local ts, req, ips, fails = rec:match("^(%d+),(%d+),(%d+),(%d+)$")
        if ts then
            out[#out + 1] = {
                ts = tonumber(ts),
                requests = tonumber(req) or 0,
                distinct_ips = tonumber(ips) or 0,
                fails = tonumber(fails) or 0,
            }
        end
    end
    return out
end

--- Append or replace one record in a series, keeping the newest N.
local function series_put(raw, rec, keep)
    local records = decode_records(raw)
    local replaced = false
    for i, r in ipairs(records) do
        if r.ts == rec.ts then
            records[i] = rec
            replaced = true
            break
        end
    end
    if not replaced then
        records[#records + 1] = rec
    end
    table.sort(records, function(a, b) return a.ts < b.ts end)
    while #records > keep do table.remove(records, 1) end
    return encode_records(records)
end

-- The last minute already folded. A timer that fires twice in the same
-- wall-clock minute (clock step, delayed callback) must not add that minute's
-- counters to the hourly sum twice; series_put() would replace the minute row
-- but the hour row is accumulated.
local last_folded

--- Fold one minute of live data into the history.
-- Called from the maintenance timer, not per request.
function _M.roll_history()
    local live = ngx.shared.statistics
    local hist = hist_dict()
    if not live or not hist then return end
    local now = ngx.time()
    -- Fold the minute that just ENDED, not the one in progress. The timer runs
    -- every 60s but is not aligned to the wall clock, so reading the current
    -- minute would write a snapshot taken at an arbitrary offset and lose
    -- everything recorded after it; a host whose traffic began in the second
    -- half of the minute would not be folded at all.
    local minute_ts = now - (now % 60) - 60
    if last_folded == minute_ts then return end
    last_folded = minute_ts
    for _, host in ipairs(_M.hosts(2)) do
        local base = PREFIX .. host .. ":" .. os.date("%Y%m%d%H%M", minute_ts)
        local req = tonumber(live:get(base .. ":req") or 0) or 0
        local ips = sample_distinct(live:get(base .. ":ip"))
        local fails = tonumber(live:get(base .. ":fail") or 0) or 0
        if req > 0 or ips > 0 then
            local rec = { ts = minute_ts, requests = req, distinct_ips = ips, fails = fails }
            local raw = hist:get("hist:" .. host)
            hist:set("hist:" .. host, series_put(raw, rec, HIST_MINUTES))
            -- The hour row: same counters, summed except the distinct clients,
            -- which take the maximum.
            local hour_ts = minute_ts - (minute_ts % 3600)
            local hraw = hist:get("histH:" .. host)
            local hrecords = decode_records(hraw)
            local hrec
            for i, r in ipairs(hrecords) do
                if r.ts == hour_ts then hrec = r; hrecords[i] = nil break end
            end
            hrec = hrec or { ts = hour_ts, requests = 0, distinct_ips = 0, fails = 0 }
            hrec.requests = hrec.requests + req
            hrec.distinct_ips = math.max(hrec.distinct_ips, ips)
            hrec.fails = hrec.fails + fails
            hrecords[#hrecords + 1] = hrec
            table.sort(hrecords, function(a, b) return a.ts < b.ts end)
            while #hrecords > HIST_HOURS do table.remove(hrecords, 1) end
            hist:set("histH:" .. host, encode_records(hrecords))
        end
    end
end

--- Read a host's per-minute history, oldest first.
function _M.history(host, minutes)
    local hist = hist_dict()
    if not hist then return {} end
    local records = decode_records(hist:get("hist:" .. host))
    -- The stored series holds the whole retained window; the caller asks for
    -- the most recent slice of it.
    minutes = math.min(minutes or HIST_MINUTES, HIST_MINUTES)
    if #records > minutes then
        local trimmed = {}
        for i = #records - minutes + 1, #records do trimmed[#trimmed + 1] = records[i] end
        records = trimmed
    end
    local out = {}
    for _, r in ipairs(records) do
        out[#out + 1] = {
            ts = r.ts,
            minute = os.date("%H:%M", r.ts),
            requests = r.requests,
            distinct_ips = r.distinct_ips,
            fails = r.fails,
            fail_pct = (r.requests > 0) and math.floor((r.fails / r.requests) * 1000) / 10 or 0,
            req_per_ip = (r.distinct_ips > 0) and (r.requests / r.distinct_ips) or nil,
        }
    end
    return out
end

--- Read a host's per-hour history, oldest first.
function _M.hour_history(host, hours)
    local hist = hist_dict()
    if not hist then return {} end
    local records = decode_records(hist:get("histH:" .. host))
    hours = math.min(hours or HIST_HOURS, HIST_HOURS)
    if #records > hours then
        local trimmed = {}
        for i = #records - hours + 1, #records do trimmed[#trimmed + 1] = records[i] end
        records = trimmed
    end
    local out = {}
    for _, r in ipairs(records) do
        out[#out + 1] = {
            ts = r.ts,
            hour = os.date("%m-%d %H", r.ts),
            requests = r.requests,
            distinct_ips = r.distinct_ips,
            fails = r.fails,
            fail_pct = (r.requests > 0) and math.floor((r.fails / r.requests) * 1000) / 10 or 0,
            req_per_ip = (r.distinct_ips > 0) and (r.requests / r.distinct_ips) or nil,
        }
    end
    return out
end

local function percentile(values, p)
    if #values == 0 then return nil end
    local sorted = {}
    for _, v in ipairs(values) do sorted[#sorted + 1] = v end
    table.sort(sorted)
    local idx = math.floor(p * #sorted) + 1
    if idx < 1 then idx = 1 end
    if idx > #sorted then idx = #sorted end
    return sorted[idx]
end

local function median(values)
    return percentile(values, 0.5)
end

--- What is normal for this host.
--
-- Two windows, because they answer different questions. The minute median
-- over the last three hours answers "is right now unusual for this host".
-- The hour median over the last week answers "is this host unusual at all",
-- which is what catches a slow-burn incident that never looks like a spike.
function _M.baseline(host)
    local minutes = _M.history(host, HIST_MINUTES)
    local hours = _M.hour_history(host, HIST_HOURS)
    local mreq, mips, mratio = {}, {}, {}
    for _, m in ipairs(minutes) do
        if m.requests > 0 then
            mreq[#mreq + 1] = m.requests
            mips[#mips + 1] = m.distinct_ips
            if m.req_per_ip then mratio[#mratio + 1] = m.req_per_ip end
        end
    end
    local hreq = {}
    for _, h in ipairs(hours) do
        if h.requests > 0 then hreq[#hreq + 1] = h.requests end
    end
    return {
        minutes_covered = #minutes,
        hours_covered = #hours,
        requests_median = median(mreq),
        requests_p90 = percentile(mreq, 0.9),
        distinct_ips_median = median(mips),
        req_per_ip_median = median(mratio),
        hour_requests_median = median(hreq),
        hour_requests_p90 = percentile(hreq, 0.9),
    }
end

--- Does this status code mean the BACKEND failed?
--
-- Narrow on purpose. 5xx is the backend or the path to it failing; 499 is the
-- client giving up on a response that never came; 408/504/524 are timeouts.
--
-- 403 is the WAF blocking, 404 is the backend answering correctly, and 429 is
-- the rate limiter working. None of them is a backend failure, and treating
-- them as one produces a panel that screams while the defence is doing its
-- job — which is worse than no alarm at all.
function _M.is_backend_failure(code)
    local c = tonumber(code) or 0
    if c >= 500 then return true end
    return c == 499 or c == 408 or c == 504 or c == 524
end

--- Deviation signals for one host.
-- The panel renders these; it does not have to re-derive them.
function _M.anomalies(host, series)
    local out = {}
    local base = _M.baseline(host)
    local latest = series and series[#series]
    if not latest then return out end

    -- Distributed scraping: many clients, each making about ONE request.
    --
    -- The ratio is the wrong way round to think about it. A normal visitor
    -- makes several requests (the page, its ajax calls, a profile lookup), so
    -- a normal site's requests-per-client is well ABOVE 1. The scraper that
    -- took this site down was 1.01 across 3,662 addresses: every client made
    -- exactly one request and vanished. So the signal is a ratio NEAR ONE with
    -- a lot of clients — not a low ratio.
    --
    -- The client count is checked against this host's own baseline as well,
    -- because a small site can legitimately have twenty clients a minute.
    local ratio = latest.req_per_ip
    local ips = latest.distinct_ips or 0
    local baseline_ips = base.distinct_ips_median
    local many_new_clients = (not baseline_ips) or ips > baseline_ips * 3
    if ratio and ips >= 20 and ratio <= 1.2 and many_new_clients then
        out[#out + 1] = {
            level = "warn",
            kind = "diverse_scraping",
            text = string.format(
                "%d 个不同客户端，每 IP 仅 %.2f 次请求 —— 分布式爬虫特征（正常访客会多次请求）",
                ips, ratio),
        }
    end

    -- Volume against this host's own baseline.
    if base.requests_p90 and latest.requests > base.requests_p90 * 3
        and latest.requests > 20 then
        out[#out + 1] = {
            level = "warn",
            kind = "volume_spike",
            text = string.format("请求 %d/分，是该站 p90 基线（%d）的 %.1f 倍",
                latest.requests, base.requests_p90, latest.requests / base.requests_p90),
        }
    end

    -- Failure share. What counts as a failure is narrow on purpose: 5xx, 499
    -- (the client gave up before a response arrived) and the timeout codes.
    --
    -- 403 is the WAF blocking, which is the system WORKING — counting it as a
    -- failure would have the panel cry wolf exactly when the defence is doing
    -- its job, and on this deployment the bot rule alone produces a steady
    -- stream of 403s. 404 is the backend answering correctly, and 429 is the
    -- rate limiter doing what it was configured to do.
    local status = _M.host_status_counts(host)
    local total, failing = 0, 0
    for code, n in pairs(status) do
        total = total + n
        local c = tonumber(code) or 0
        if _M.is_backend_failure(c) then failing = failing + n end
    end
    if total > 0 and failing / total > 0.2 then
        out[#out + 1] = {
            level = "critical",
            kind = "backend_failing",
            text = string.format("后端失败率 %.0f%%（%d/%d 个请求到了后端却没拿到结果）",
                failing / total * 100, failing, total),
        }
    end

    -- A traffic shape that did not exist an hour ago.
    for _, sh in ipairs(latest.shapes or {}) do
        if sh.first_seen and (ngx.time() - sh.first_seen) < 3600
            and sh.count >= math.max(5, (latest.requests or 0) * 0.2) then
            out[#out + 1] = {
                level = "info",
                kind = "new_shape",
                text = string.format("新的流量形状（占比 %.0f%%）：%s",
                    (latest.requests or 0) > 0 and sh.count / latest.requests * 100 or 0,
                    (sh.shape or ""):sub(1, 90)),
            }
        end
    end
    return out
end

--- Host-level status counts for the current minute, read from the live data.
function _M.host_status_counts(host)
    local shared = ngx.shared.statistics
    if not shared then return {} end
    -- The live module does not keep a status breakdown per minute; the
    -- statistics engine keeps it per host per bucket. Reading the 1m bucket is
    -- the freshest view, and the rollup keeps it available.
    local statistics = require "core.statistics"
    local st = statistics.get_host_status(host, "1m")
    local out = {}
    for code, n in pairs(st) do
        out[code] = n
    end
    return out
end

--- Start the history rollup timer.
-- Worker 0 only: the rollup writes one row per host per minute, and running
-- it in every worker would multiply that and contend on the same keys.
function _M.init()
    if not ngx.timer or not ngx.timer.every then return end
    if ngx.worker.id() ~= 0 then return end
    -- Every 60s, slightly after the minute turns over, so the minute being
    -- folded is the one that just ended.
    ngx.timer.every(60, function(premature)
        if premature then return end
        local ok, err = pcall(function() _M.roll_history() end)
        if not ok then
            ngx.log(ngx.WARN, "live_stats: history rollup failed: ", tostring(err))
        end
    end)
    -- The database collector runs here too, so its reading is available
    -- without the panel having to trigger it.
    ngx.timer.every(60, function(premature)
        if premature then return end
        local ok, mysql = pcall(function()
            return require("core.mysql_monitor").collect()
        end)
        if not ok then
            ngx.log(ngx.WARN, "mysql_monitor: collection failed: ", tostring(mysql))
        end
    end)
end

return _M
