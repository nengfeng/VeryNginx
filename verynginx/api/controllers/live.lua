-- -*- coding: utf-8 -*-
-- @Disc    : live traffic panel API — what the dashboard could not show
--
-- WHY THIS ENDPOINT EXISTS
-- ----------------------
-- During the 2026-10 incident the dashboard showed nothing while the site was
-- failing, and the reason was structural rather than cosmetic. The panel's
-- traffic view is built on per-uri counters: how many requests each path got,
-- and which rules fired. Three things an operator needs during an attack were
-- not in that model at all:
--
--   * How many distinct clients are hitting us, and how many requests each
--     one makes. A normal forum is ~0.2 requests per client; the scraper that
--     took the site down was 1.01, from 3,662 different addresses in five
--     minutes. That ratio was read out of the access log by hand.
--   * What the traffic looks like — which user agent family, which path
--     shape, does it carry a cookie or a referer. A scraper that mirrors a
--     browser is not distinguishable by path.
--   * What the BACKEND returned. 99.4% of inbound requests ended in 499/502
--     and the panel could not show a single one of them, because the status
--     codes that describe an overloaded site were not in the recorded set and
--     there was no host-level rollup to sum.
--
-- This endpoint serves the live view: a per-minute series per host (requests,
-- distinct clients, requests-per-client, traffic shapes), the host-level
-- status distribution, and the backend's own health.
--
-- Every traffic number here is a SAMPLE: the statistics engine samples one
-- request in ten. The sample rate is reported alongside the numbers, because a
-- count that is silently ten times low is worse than no count at all.

local _M = {}

local json = require "dkjson"
local statistics = require "core.statistics"
local live_stats = require "core.live_stats"

-- Where the log files live. The directory is the LNMP convention; the FILE
-- LIST is discovered, not hardcoded. Baking one deployment's site names into
-- the product both leaks those domains and leaves the panel empty on every
-- other install. When lfs is unavailable, fall back to the two generic names.
local LOG_DIR = "/data/wwwlogs"
local LOG_CACHE_TTL = 60
local MAX_LOG_FILES = 32
local FALLBACK_LOGS = { "error_nginx.log", "access_nginx.log" }

local log_cache = { at = 0, names = nil }

local function log_files()
    local now = ngx.now()
    if log_cache.names and (now - log_cache.at) < LOG_CACHE_TTL then
        return log_cache.names
    end
    local names = {}
    local ok, lfs = pcall(require, "lfs")
    if ok then
        local ok_dir, iter, dir_obj = pcall(lfs.dir, LOG_DIR)
        if ok_dir then
            for name in iter, dir_obj do
                if name:match("%.log$") then
                    names[#names + 1] = name
                end
            end
        end
    end
    if #names == 0 then
        for _, name in ipairs(FALLBACK_LOGS) do
            names[#names + 1] = name
        end
    end
    table.sort(names)
    while #names > MAX_LOG_FILES do
        table.remove(names)
    end
    log_cache.at, log_cache.names = now, names
    return names
end

--- Read a file's size without pulling its contents into memory.
-- The error log reached 1.98 GB in a day during the incident; reading it to
-- measure it would be absurd.
local function file_size(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local size = f:seek("end")
    f:close()
    return size
end

--- Disk usage of the log volume, in bytes free and percent used.
-- statvfs is not exposed to Lua, so this shells out to df. The log volume was
-- the one thing that grew unnoticed during the incident, so the panel reports
-- it rather than leaving it to be noticed by accident.
local disk_cache = { at = 0, value = nil }
local DISK_CACHE_TTL = 30

local function disk_usage()
    local now = ngx.now()
    if disk_cache.value and (now - disk_cache.at) < DISK_CACHE_TTL then
        return disk_cache.value
    end
    local out = {}
    local stat = io.popen("df -k " .. LOG_DIR .. " 2>/dev/null | tail -1")
    if not stat then return out end
    for line in stat:lines() do
        local total, used, avail = line:match("%s(%d+)%s+(%d+)%s+(%d+)")
        if total then
            out.total_bytes = tonumber(total) * 1024
            out.used_bytes = tonumber(used) * 1024
            out.free_bytes = tonumber(avail) * 1024
            out.used_pct = math.floor((tonumber(used) / tonumber(total)) * 1000) / 10
        end
    end
    stat:close()
    disk_cache.at, disk_cache.value = now, out
    return out
end

--- PHP-FPM pool state, if the status path is reachable.
--
-- php-fpm serves its status page over FastCGI at pm.status_path. nginx has
-- to forward it, and the forwarding location is restricted to 127.0.0.1, so
-- this reads it over the loopback rather than exposing it publicly.
local function fpm_status()
    local out = { available = false }
    local httpc = require "resty.http".new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri("http://127.0.0.1/php-fpm_status", {
        method = "GET",
    })
    if not res then
        out.error = tostring(err)
        return out
    end
    if res.status ~= 200 or not res.body then
        out.error = "status " .. tostring(res.status)
        return out
    end
    out.available = true
    -- php-fpm's status page is "key: value" with spaces in the key
    -- ("active processes: 1"), and the values are not all numeric
    -- ("process manager: dynamic"). Normalise the key to snake_case so the
    -- panel has stable names to read.
    --
    -- The body is split into lines first: a Lua pattern's "^" anchors to the
    -- start of the WHOLE subject, not of each line, so gmatch with "^" would
    -- only ever match the first line.
    for line in (res.body .. "\n"):gmatch("(.-)\n") do
        local k, v = line:match("^([%a][%a ]-):%s*(%S+)%s*$")
        if k then
            local key = k:gsub("%s+", "_"):lower()
            out[key] = tonumber(v) or v
        end
    end
    return out
end

--- Sizes of the log files, and how fast they are growing.
-- Growth is measured against a previous reading of the same file, kept in the
-- shared dict, so the panel can show "the error log grew 400 MB in the last
-- hour" instead of leaving the operator to notice a 2 GB file by accident.
local function log_sizes()
    local shared = ngx.shared.metrics
    local out = {}
    local now = ngx.now()
    for _, name in ipairs(log_files()) do
        local path = LOG_DIR .. "/" .. name
        local size = file_size(path)
        if size then
            local entry = { name = name, bytes = size }
            if shared then
                local prev = shared:get("log_size:" .. name)
                local prev_ts = tonumber(shared:get("log_size_ts:" .. name) or 0)
                if prev and prev_ts > 0 and now > prev_ts then
                    local dt = now - prev_ts
                    entry.growth_bps = math.floor((size - tonumber(prev or 0)) / dt)
                    entry.growth_window_s = math.floor(dt)
                end
                shared:set("log_size:" .. name, size)
                shared:set("log_size_ts:" .. name, now)
            end
            out[#out + 1] = entry
        end
    end
    return out
end

--- One host's live view.
local function host_view(host, minutes)
    local series = live_stats.host_series(host, minutes)
    local latest = series[#series] or {}
    local status = statistics.get_host_status(host, "1m")
    local total = 0
    for _, n in pairs(status) do total = total + n end
    local failing = 0
    for code, n in pairs(status) do
        -- Same definition as the anomaly check: 5xx, 499 and the timeouts.
        -- 403 is the WAF blocking and 429 is the rate limiter working, so
        -- counting them as failures would report the defence as a failure.
        if live_stats.is_backend_failure(code) then failing = failing + n end
    end
    -- What is normal for this host, so the current minute can be judged
    -- against something instead of against nothing.
    local baseline = live_stats.baseline(host)
    local anomalies = live_stats.anomalies(host, series)
    return {
        host = host,
        series = series,
        -- The longer per-minute history and the hourly view. These are what
        -- turn a snapshot into a trend: "74%" means nothing, "74% and climbing
        -- since 14:00" is an alarm.
        history = live_stats.history(host, 180),
        hours = live_stats.hour_history(host, 168),
        baseline = baseline,
        anomalies = anomalies,
        status = status,
        status_total = total,
        -- Share of the host's traffic that came back as an error other than a
        -- rate-limit rejection. A rate limit is a success; a 502 is not.
        failing_pct = (total > 0) and math.floor((failing / total) * 1000) / 10 or 0,
        shapes = latest.shapes or {},
    }
end

local function handle_live()
    local minutes = tonumber(ngx.var.arg_minutes) or 10
    if minutes < 1 then minutes = 1 end
    if minutes > 30 then minutes = 30 end

    local hosts = {}
    for _, h in ipairs(live_stats.hosts(minutes)) do
        hosts[#hosts + 1] = host_view(h, minutes)
    end
    table.sort(hosts, function(a, b) return a.host < b.host end)

    -- Every anomaly across every host, most severe first, so the operator
    -- sees what is wrong without reading each host.
    local anomalies = {}
    for _, h in ipairs(hosts) do
        for _, a in ipairs(h.anomalies or {}) do
            a.host = h.host
            anomalies[#anomalies + 1] = a
        end
    end
    local order = { critical = 1, warn = 2, info = 3 }
    table.sort(anomalies, function(a, b)
        return (order[a.level] or 9) < (order[b.level] or 9)
    end)

    local data = {
        generated_at = ngx.now(),
        sample_rate = 10,
        minutes = minutes,
        hosts = hosts,
        anomalies = anomalies,
        backend = {
            -- These come straight from nginx's own counters, in the request
            -- context — no extra scrape. "writing" high with "waiting" high
            -- means responses are backed up behind a slow upstream, which is
            -- the signature of the overload that took the site down.
            nginx = {
                active = tonumber(ngx.var.connections_active) or 0,
                reading = tonumber(ngx.var.connections_reading) or 0,
                writing = tonumber(ngx.var.connections_writing) or 0,
                waiting = tonumber(ngx.var.connections_waiting) or 0,
            },
            fpm = fpm_status(),
            -- The database the site runs on. On 2026-10 this was the component
            -- that was actually overloaded while the WAF's own panel showed a
            -- healthy site.
            mysql = require("core.mysql_monitor").last(),
            disk = disk_usage(),
            logs = log_sizes(),
        },
    }
    return json.encode({ ret = "success", data = data })
end

function _M.register(api)
    api.register("GET", "/live", handle_live, true)
end

return _M
