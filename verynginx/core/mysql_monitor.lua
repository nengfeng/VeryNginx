-- -*- coding: utf-8 -*-
-- @Disc    : MySQL visibility — the database the site actually runs on
--
-- WHY THIS EXISTS
-- ---------------
-- On 2026-10 the box was taken down by a database problem that the WAF could
-- not see at all. phpBB's session table had grown to 10,219,298 rows / 5.1 GB
-- because its garbage collector had not run since 2024-11, and the "who is
-- online" count had to scan all of it on every page render. MariaDB went to
-- 77% CPU, the fastcgi backlog filled, and 99.4% of inbound requests failed
-- with 499/502 — while the WAF's own panel showed a perfectly healthy site
-- with zero attacks.
--
-- Nothing in the WAF looked at the database. It is the component that was
-- actually overloaded, and it is the component whose state decides whether
-- the site is up.
--
-- WHAT IT READS
-- -------------
-- Connections and load (Threads_connected / Threads_running /
-- Max_used_connections), the slow-query counter, the row count of the tables
-- the operator nominated, and the shape of the queries currently running.
-- The row counts are the part that matters: a table that only ever grows is a
-- leak, and a leak is invisible until it has taken the site down.
--
-- HOW IT CONNECTS
-- ---------------
-- Through lua-resty-mysql over a cosocket, with one connection kept open
-- between collections.
--
-- It used to shell out to the mysql client with io.popen, and that was a poor
-- choice for two reasons. Forking a process inside an nginx worker is not
-- something to do routinely — the workers here are 77-119 MB resident, so
-- every fork pays for copy-on-write — and it made the collector depend on an
-- external binary. It already had: an nginx worker inherits the master's
-- minimal PATH, which does not contain /usr/local/mariadb/bin, so a bare
-- "mysql" resolved to nothing and the collection silently returned empty, which
-- reads exactly like "the monitor found nothing". A dependency that fails
-- quietly is worse than one that fails loudly.
--
-- CREDENTIALS
-- -----------
-- Read from a MySQL defaults-file outside the config and outside the
-- repository, like the one /usr/local/sbin/phpbb-session-gc.php uses. The WAF
-- is a general product; baking one site's database password into the config
-- would be wrong, and the config is served to the panel.
--
-- The monitor is OFF unless config.mysql_monitor.enabled is true, and it
-- needs no privileges beyond reading the status variables and the nominated
-- tables' row counts.

local _M = {}

local dict_guard = require "core.dict_guard"
local json = require "dkjson"

local DEFAULTS = {
    enabled = false,
    -- A MySQL defaults-file: [client] user=... password=... socket=...
    -- The credentials stay in a file the config points at, never in the config
    -- itself, which is served to the panel.
    cnf = "/opt/verynginx/configs/mysql-monitor.cnf",
    -- Tables whose row count is worth watching, as { database = { table, ... } }.
    tables = {},
    -- How many distinct query shapes to report.
    top_queries = 8,
}

local function cfg()
    local ok, config = pcall(require, "core.config")
    if not ok or not config then return DEFAULTS end
    local m = config.mysql_monitor
    if type(m) ~= "table" then return DEFAULTS end
    return {
        enabled = m.enabled == true,
        cnf = type(m.cnf) == "string" and m.cnf ~= "" and m.cnf or DEFAULTS.cnf,
        tables = type(m.tables) == "table" and m.tables or DEFAULTS.tables,
        top_queries = tonumber(m.top_queries) or DEFAULTS.top_queries,
    }
end

-- ---------------------------------------------------------------------------
-- Credentials
-- ---------------------------------------------------------------------------
--
-- Read from the MySQL defaults-file rather than from the config. Two reasons:
-- the config is served to the panel, and a password in it would be handed to
-- anyone who can open the dashboard.
--
-- The file is parsed here rather than handed to a client binary, because the
-- point of moving off the CLI is to stop depending on an external binary:
-- an nginx worker inherits the master's minimal PATH, which does not contain
-- /usr/local/mariadb/bin, and a bare "mysql" there resolves to nothing — the
-- collection silently returned empty, which reads exactly like "the monitor
-- found nothing".
local function read_credentials(path)
    local creds = {}
    local f = io.open(path, "r")
    if not f then return nil, "credentials file not readable: " .. path end
    local in_client = false
    for line in f:lines() do
        line = line:gsub("#.*$", "")
        line = line:gsub("^%s+", ""):gsub("%s+$", "")
        if line:match("^%[.*%]$") then
            -- A section header: only [client] holds what we need.
            in_client = (line == "[client]")
        elseif in_client and line ~= "" then
            local k, v = line:match("^([^=]+)=(.*)$")
            if k then
                k = k:gsub("^%s+", ""):gsub("%s+$", "")
                v = v:gsub("^%s+", ""):gsub("%s+$", "")
                creds[k:lower()] = v
            end
        end
    end
    f:close()
    if not creds.user then return nil, "no user in " .. path end
    return creds
end

-- ---------------------------------------------------------------------------
-- Connection
-- ---------------------------------------------------------------------------
--
-- A single connection, kept open between collections. The collector runs on
-- worker 0's timer, so only that worker holds one. A cosocket that goes stale
-- (server closed it) is detected by the query failing, which drops the
-- connection so the next collection reconnects.
local conn = nil

local function drop_conn()
    if conn then
        pcall(function() conn:close() end)
        conn = nil
    end
end

local function get_conn()
    if conn then return conn end
    local ok, mysql = pcall(require, "resty.mysql")
    if not ok then
        return nil, "lua-resty-mysql is not available: " .. tostring(mysql)
    end
    local c = cfg()
    local creds, cerr = read_credentials(c.cnf)
    if not creds then return nil, cerr end
    local m = mysql:new()
    m:set_timeout(2000)
    local opts = {
        user = creds.user,
        password = creds.password,
    }
    if creds.socket and creds.socket ~= "" then
        opts.path = creds.socket
    else
        opts.host = creds.host or "127.0.0.1"
        opts.port = tonumber(creds.port) or 3306
    end
    local cok, cerr2 = m:connect(opts)
    if not cok then
        return nil, "connect failed: " .. tostring(cerr2)
    end
    conn = m
    return conn
end

--- Run a query and return the rows as tab-separated strings.
-- The same shape the CLI client produced, so the parsing above is unchanged.
local function query(sql)
    local c = cfg()
    if not c.enabled then return nil end
    local m, err = get_conn()
    if not m then return nil, err end
    local res, qerr = m:query(sql)
    if not res then
        -- A stale or broken connection: drop it so the next attempt makes a
        -- new one.
        drop_conn()
        return nil, qerr
    end
    local out = {}
    for i = 1, #res do
        local row = res[i]
        if type(row) == "table" then
            local parts = {}
            for j = 1, #row do
                local v = row[j]
                if v == nil or v == ngx.null then v = "" end
                parts[j] = tostring(v)
            end
            out[#out + 1] = table.concat(parts, "\t")
        else
            out[#out + 1] = tostring(row)
        end
    end
    return out
end

--- Normalise a query into a shape: literals become ?, so the same statement
--- from many callers counts once.
local function normalize_sql(sql)
    if not sql then return "" end
    local s = sql:gsub("%d+", "?"):gsub("'[^']*'", "?"):gsub("%s+", " ")
    if #s > 160 then s = s:sub(1, 160) end
    return s
end

--- One collection pass.
-- @return table|nil
function _M.collect()
    local c = cfg()
    if not c.enabled then return nil end

    local status = {}
    local rows = query(
        "SHOW GLOBAL STATUS WHERE Variable_name IN " ..
        "('Threads_connected','Threads_running','Max_used_connections'," ..
        "'Slow_queries','Questions','Uptime','Aborted_connects')")
    if not rows then return nil, "status query failed" end
    for _, line in ipairs(rows) do
        local k, v = line:match("^(%S+)%s+(%S+)$")
        if k then
            status[k:lower()] = tonumber(v) or v
        end
    end

    -- Row counts of the nominated tables. information_schema.TABLES is
    -- approximate for InnoDB (it is the last estimate), which is fine for
    -- spotting a table that is growing without bound.
    --
    -- The previous reading is compared here, while both are in hand. A table
    -- that only ever grows is a leak, and the incident's session table went
    -- from 70,957 to 10,219,298 rows over two years without anyone seeing it,
    -- because nothing compared one reading with the next.
    -- The statistics dict, not a dedicated one: a new shared-memory zone is
    -- created by the master, so it would need a full nginx restart to exist,
    -- and that on a live box means clearing the rate-limit counters, the
    -- reputation data and the statistics all at once. Twelve extra keys in a
    -- dictionary that is 9% full cost nothing measurable.
    local shared = ngx.shared.statistics
    local tables = {}
    for db, list in pairs(c.tables) do
        tables[db] = {}
        for _, t in ipairs(list) do
            local r = query(string.format(
                "SELECT TABLE_ROWS, ROUND((DATA_LENGTH+INDEX_LENGTH)/1048576,1) " ..
                "FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s",
                string.format("%q", db), string.format("%q", t)))
            if r and r[1] then
                local rows_est, mb = r[1]:match("^(%d+)%s+(%S+)$")
                rows_est = tonumber(rows_est) or 0
                local prev, prev_ts = 0, 0
                if shared then
                    prev = tonumber(shared:get("mysql:rows:" .. db .. ":" .. t) or 0) or 0
                    prev_ts = tonumber(shared:get("mysql:rows_ts:" .. db .. ":" .. t) or 0) or 0
                end
                tables[db][t] = {
                    rows = rows_est,
                    mb = tonumber(mb) or 0,
                    previous_rows = prev,
                    growth = rows_est - prev,
                    window_s = (prev_ts > 0) and (ngx.now() - prev_ts) or nil,
                }
                if shared then
                    dict_guard.set(shared, "live.mysql", "mysql:rows:" .. db .. ":" .. t, rows_est)
                    dict_guard.set(shared, "live.mysql", "mysql:rows_ts:" .. db .. ":" .. t, ngx.now())
                end
            end
        end
    end

    -- The queries running right now, by shape. This is where the cost of an
    -- incident shows up: during the outage, twelve copies of the same
    -- COUNT(DISTINCT ...) were running at once, each holding a table scan.
    local running = {}
    local proc = query(
        "SELECT INFO, TIME FROM information_schema.PROCESSLIST " ..
        "WHERE COMMAND <> 'Sleep' AND INFO IS NOT NULL ORDER BY TIME DESC LIMIT 50")
    if proc then
        local counts = {}
        for _, line in ipairs(proc) do
            local info, t = line:match("^(.*)%s+(%d+)$")
            if info and info ~= "" then
                local shape = normalize_sql(info)
                counts[shape] = (counts[shape] or 0) + 1
                if t and (tonumber(t) or 0) >= 1 then
                    running[#running + 1] = { shape = shape, seconds = tonumber(t) }
                end
            end
        end
        local top = {}
        for shape, n in pairs(counts) do
            top[#top + 1] = { shape = shape, concurrent = n }
        end
        table.sort(top, function(a, b) return a.concurrent > b.concurrent end)
        for i = #top, c.top_queries + 1, -1 do top[i] = nil end
        running = top
    end

    local out = {
        collected_at = ngx.now(),
        status = status,
        tables = tables,
        running = running,
    }
    -- Keep the reading so the panel can read it without the collector running
    -- on every poll: a collection spawns a mysql client, and a panel poll
    -- every few seconds would spawn one every few seconds.
    local ok, encoded = pcall(json.encode, out)
    if ok then
        dict_guard.set(ngx.shared.statistics, "live.mysql", "mysql:last", encoded)
    end
    return out
end

--- The last collected reading, or nil if the monitor is off.
function _M.last()
    local shared = ngx.shared.statistics
    if not shared then return nil end
    local raw = shared:get("mysql:last")
    if not raw then return nil end
    local ok, decoded = pcall(json.decode, raw)
    if not ok then return nil end
    return decoded
end

return _M
