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

-- Where the log files live, and how many of them to report growth for.
local LOG_DIR = "/data/wwwlogs"
local LOG_FILES = {
    "error_nginx.log",
    "access_nginx.log",
    "www.hostwyn.com_nginx.log",
    "my.gongyi.info_nginx.log",
    "gongyi.info_nginx.log",
}

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
local function disk_usage()
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
    for _, name in ipairs(LOG_FILES) do
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
        local c = tonumber(code) or 0
        if c >= 400 and c ~= 429 then failing = failing + n end
    end
    return {
        host = host,
        series = series,
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

    local data = {
        generated_at = ngx.now(),
        sample_rate = 10,
        minutes = minutes,
        hosts = hosts,
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
