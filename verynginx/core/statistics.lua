-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : statistics engine - time-windowed request counting, LRU index, persistence
--            per-host dimension: keys are <bucket>:<host>:<uri>, each host keeps
--            its own uri LRU index, plus a global host LRU (hosts:<bucket>).

local _M = {}
local config = require "core.config"
local dict_guard = require "core.dict_guard"
local json = pcall(require, "cjson") and require("cjson") or require("dkjson")

-- Log request sample rate: 1-in-10 requests update shdict stats
local LOG_SAMPLE_RATE = 10
local _common_codes = { "200", "301", "302", "304", "400", "401", "403", "404", "405", "500", "502", "503" }

-- ---------------------------------------------------------------------------
-- LRU index helpers (stored in shared dict)
-- ---------------------------------------------------------------------------
local function lru_add(shared, index_key, value, max_keys)
    local data = shared:get(index_key)
    local list = {}
    if data then
        local ok, decoded = pcall(json.decode, data)
        if ok then
            list = decoded
        end
    end
    -- Remove if exists (move to front)
    for i = #list, 1, -1 do
        if list[i] == value then
            table.remove(list, i)
        end
    end
    -- Add to front
    table.insert(list, 1, value)
    -- Trim to max
    while #list > max_keys do
        table.remove(list)
    end
    dict_guard.set(shared, "stats.lru", index_key, json.encode(list))
end

local function lru_list(shared, index_key)
    local data = shared:get(index_key)
    if not data then
        return {}
    end
    local ok, decoded = pcall(json.decode, data)
    if ok then
        return decoded
    end
    return {}
end

-- ---------------------------------------------------------------------------
-- URI normalization
-- ---------------------------------------------------------------------------
function _M.normalize_uri(uri)
    if not uri then
        return "/"
    end
    -- Remove query string
    local qpos = uri:find("?")
    if qpos then
        uri = uri:sub(1, qpos - 1)
    end
    -- Normalize parameterized segments: /user/123 → /user/:id, /hash/abc → /hash/:hex
    -- single gsub with callback avoids two-pass interference (/123abc → /:idabc)
    -- skip entirely if no hex chars present (fast path for common URIs)
    if uri:find("[0-9a-fA-F]") then
        uri = uri:gsub("/([0-9a-fA-F]+)", function(m)
            if m:match("^%d+$") then return "/:id" end
            return "/:hex"
        end)
    end
    return uri
end

-- ---------------------------------------------------------------------------
-- Host normalization
-- ---------------------------------------------------------------------------
-- Normalize ngx.var.host into a dict-key-safe token: lowercase, strip a
-- trailing dot, replace key-separator chars ([ ] :) in IPv6 literals, and
-- bound length so a hostile Host header cannot balloon dict keys.
function _M.normalize_host(host)
    if not host or host == "" then
        if ngx and ngx.var then
            host = ngx.var.server_name or ""
        else
            host = ""
        end
    end
    host = tostring(host):lower()
    host = host:gsub("%.$", "")
    host = host:gsub("[:%[%]]", "_")
    if #host > 64 then
        host = host:sub(1, 64)
    end
    if host == "" then
        host = "_"
    end
    return host
end

-- Validate an external `host` query parameter (from /summary, /stats/top-paths,
-- /stats/hosts). Only normalized tokens (what get_hosts() emits) are accepted,
-- so a crafted value can never forge or scan dict keys.
function _M.valid_host_param(host)
    if type(host) ~= "string" then return false end
    if #host == 0 or #host > 64 then return false end
    return host:match("^[%w_%-%.]+$") ~= nil
end

-- ---------------------------------------------------------------------------
-- Config helpers
-- ---------------------------------------------------------------------------
local function get_max_hosts()
    return (config and config.statistics and config.statistics.max_hosts) or 50
end

-- Per-host uri LRU budget: global max_uri_keys spread across max_hosts so the
-- 20m statistics dict never balloons to max_uri_keys × max_hosts keys. At the
-- single-host end the full budget is available; with many hosts each keeps at
-- least 10 URIs.
local function per_host_uri_limit()
    local max_uri = (config and config.statistics and config.statistics.max_uri_keys) or 10000
    local max_hosts = get_max_hosts()
    local per = -math.floor(-(max_uri / max_hosts))
    if per < 10 then per = 10 end
    return per
end

local function _get_seen_codes(shared, key)
    local codes = {}
    for _, c in ipairs(_common_codes) do
        local sc = shared:get(key .. ":status_" .. c)
        if sc and sc > 0 then
            codes[#codes + 1] = c
        end
    end
    return codes
end

-- Read a full entry (count/bytes/time/status) for a stats key prefix.
-- Returns nil when the key has no recorded requests.
local function read_entry(shared, key)
    local count = shared:get(key .. ":count") or 0
    if count <= 0 then
        return nil
    end
    local entry = {
        count = count,
        bytes = shared:get(key .. ":bytes") or 0,
        time = shared:get(key .. ":time") or 0,
        status = {},
    }
    local codes = _get_seen_codes(shared, key)
    for _, c in ipairs(codes) do
        local sc = shared:get(key .. ":status_" .. c)
        if sc and sc > 0 then
            entry.status[c] = sc
        end
    end
    return entry
end

-- ---------------------------------------------------------------------------
-- Initialization
-- ---------------------------------------------------------------------------
function _M.init()
    if ngx.worker.id() ~= 0 then
        return
    end

    local persist_interval = (config and config.statistics and config.statistics.persist_interval) or 300
    ngx.timer.every(60, function()
        _M._flush_bucket("1m", "5m")
    end)
    ngx.timer.every(300, function()
        _M._flush_bucket("5m", "1h")
    end)
    ngx.timer.every(3600, function()
        _M._flush_bucket("1h", "all")
    end)
    ngx.timer.every(persist_interval, function()
        _M.persist()
    end)
    -- Persist on worker shutdown (flush short-term buckets into "all" first)
    local function persist_on_exit(premature)
        if premature then return end
        if ngx.worker.exiting() then
            _M._flush_bucket("1m", "5m")
            _M._flush_bucket("5m", "1h")
            _M._flush_bucket("1h", "all")
            _M.persist()
            return
        end
        ngx.timer.at(1, persist_on_exit)
    end
    ngx.timer.at(1, persist_on_exit)
    _M.restore()
end

-- ---------------------------------------------------------------------------
-- Per-request logging
-- ---------------------------------------------------------------------------
function _M.log_request(_)
    -- Sample: only LOG_SAMPLE_RATE-in-1 update detailed stats
    if math.random(LOG_SAMPLE_RATE) ~= 1 then return end

    local status = tonumber(ngx.var.status) or 0
    local bytes = tonumber(ngx.var.body_bytes_sent) or 0
    local time = tonumber(ngx.var.request_time) or 0
    local uri = _M.normalize_uri(ngx.var.uri)
    local host = _M.normalize_host(ngx.var.host)

    local shared = ngx.shared.statistics
    if not shared then
        return
    end

    local per_host = per_host_uri_limit()
    local key = "1m:" .. host .. ":" .. uri
    dict_guard.incr(shared, "stats.1m", key .. ":count", 1, 0)
    dict_guard.incr(shared, "stats.1m", key .. ":bytes", bytes, 0)
    dict_guard.incr(shared, "stats.1m", key .. ":time", time, 0)
    local code_idx = status
    dict_guard.incr(shared, "stats.1m", key .. ":status_" .. code_idx, 1, 0)
    -- Update per-host uri LRU and global host LRU on sampled requests
    lru_add(shared, "index:1m:" .. host, uri, per_host)
    lru_add(shared, "hosts:1m", host, get_max_hosts())
end

-- ---------------------------------------------------------------------------
-- get_top_paths  — return the top-N URIs by request count
-- ---------------------------------------------------------------------------
function _M.get_top_paths(limit, host)
    local shared = ngx.shared.statistics
    if not shared then return {} end

    local hosts
    if host and host ~= "" then
        hosts = { host }
    else
        hosts = lru_list(shared, "hosts:1m")
    end

    local results = {}
    for _, h in ipairs(hosts) do
        local uris = lru_list(shared, "index:1m:" .. h)
        for _, uri in ipairs(uris) do
            local key = "1m:" .. h .. ":" .. uri
            local count = tonumber(shared:get(key .. ":count") or 0)
            local bytes = tonumber(shared:get(key .. ":bytes") or 0)
            local time = tonumber(shared:get(key .. ":time") or 0)
            if count > 0 then
                results[#results + 1] = { uri = uri, count = count, bytes = bytes, time = time }
            end
        end
    end
    table.sort(results, function(a, b) return a.count > b.count end)
    if limit and #results > limit then
        local trimmed = {}
        for i = 1, limit do
            trimmed[i] = results[i]
        end
        return trimmed
    end
    return results
end

-- ---------------------------------------------------------------------------
-- Bucket flushing
-- ---------------------------------------------------------------------------
function _M._flush_bucket(src_bucket, dst_bucket)
    local shared = ngx.shared.statistics
    if not shared then
        return
    end
    local hosts = lru_list(shared, "hosts:" .. src_bucket)
    local per_host = per_host_uri_limit()
    local max_hosts = get_max_hosts()

    for _, host in ipairs(hosts) do
        local uris = lru_list(shared, "index:" .. src_bucket .. ":" .. host)
        local flushed = false
        for _, uri in ipairs(uris) do
            local src_key = src_bucket .. ":" .. host .. ":" .. uri
            local count = shared:get(src_key .. ":count") or 0
            local bytes = shared:get(src_key .. ":bytes") or 0
            local time = shared:get(src_key .. ":time") or 0
            local codes = _get_seen_codes(shared, src_key)

            if count > 0 then
                flushed = true
                local dst_key = dst_bucket .. ":" .. host .. ":" .. uri
                dict_guard.incr(shared, "stats.rollup", dst_key .. ":count", count, 0)
                dict_guard.incr(shared, "stats.rollup", dst_key .. ":bytes", bytes, 0)
                dict_guard.incr(shared, "stats.rollup", dst_key .. ":time", time, 0)
                lru_add(shared, "index:" .. dst_bucket .. ":" .. host, uri, per_host)
                -- Merge status codes (only codes that were actually recorded)
                for _, c in ipairs(codes) do
                    local sc = shared:get(src_key .. ":status_" .. c)
                    if sc and sc > 0 then
                        dict_guard.incr(shared, "stats.rollup", dst_key .. ":status_" .. c, sc, 0)
                    end
                end
            end
            -- Clear source bucket
            shared:delete(src_key .. ":count")
            shared:delete(src_key .. ":bytes")
            shared:delete(src_key .. ":time")
            for _, c in ipairs(codes) do
                shared:delete(src_key .. ":status_" .. c)
            end
        end
        shared:delete("index:" .. src_bucket .. ":" .. host)
        -- Carry the host forward into the destination bucket's host index
        if flushed then
            lru_add(shared, "hosts:" .. dst_bucket, host, max_hosts)
        end
    end
    shared:delete("hosts:" .. src_bucket)
end

-- ---------------------------------------------------------------------------
-- Report generation
-- ---------------------------------------------------------------------------
function _M.report(period, host)
    period = period or "short"
    local bucket = "1m"
    if period == "long" then
        bucket = "all"
    elseif period == "short" then
        bucket = "1m"
    elseif period == "medium" then
        bucket = "5m"
    end

    local shared = ngx.shared.statistics
    if not shared then
        return "{}"
    end

    local hosts
    if host and host ~= "" then
        hosts = { host }
    else
        hosts = lru_list(shared, "hosts:" .. bucket)
    end

    local report = {}
    for _, h in ipairs(hosts) do
        local uris = lru_list(shared, "index:" .. bucket .. ":" .. h)
        for _, uri in ipairs(uris) do
            local entry = read_entry(shared, bucket .. ":" .. h .. ":" .. uri)
            if entry then
                local existing = report[uri]
                if existing then
                    -- Aggregate: same URI seen under multiple hosts must be
                    -- summed, not overwritten.
                    existing.count = existing.count + entry.count
                    existing.bytes = existing.bytes + entry.bytes
                    existing.time = existing.time + entry.time
                    for code, cnt in pairs(entry.status) do
                        existing.status[code] = (existing.status[code] or 0) + cnt
                    end
                else
                    report[uri] = entry
                end
            end
        end
    end

    -- Round time once at the end (millisecond precision)
    for _, e in pairs(report) do
        e.time = math.floor(((e.time or 0) * 1000) + 0.5) / 1000
    end

    return json.encode(report)
end

-- ---------------------------------------------------------------------------
-- Host listing
-- ---------------------------------------------------------------------------
function _M.get_hosts()
    local shared = ngx.shared.statistics
    if not shared then return {} end
    local seen = {}
    local result = {}
    for _, bucket in ipairs({ "1m", "all" }) do
        for _, host in ipairs(lru_list(shared, "hosts:" .. bucket)) do
            if not seen[host] then
                seen[host] = true
                result[#result + 1] = host
            end
        end
    end
    table.sort(result)
    return result
end

-- ---------------------------------------------------------------------------
-- Persistence to disk
-- ---------------------------------------------------------------------------
function _M.persist()
    local shared = ngx.shared.statistics
    if not shared then
        return
    end
    local path = _M._json_path()
    local hosts = lru_list(shared, "hosts:all")

    local data = {}
    for _, host in ipairs(hosts) do
        local uris = lru_list(shared, "index:all:" .. host)
        local per_host = {}
        for _, uri in ipairs(uris) do
            local entry = read_entry(shared, "all:" .. host .. ":" .. uri)
            if entry then
                per_host[uri] = entry
            end
        end
        if next(per_host) then
            data[host] = per_host
        end
    end

    -- Atomic write via tmp + rename; v2 payload nests entries under host.
    local tmp_path = path .. ".tmp"
    local f = io.open(tmp_path, "w")
    if f then
        f:write(json.encode({ v = 2, data = data }, { indent = true }))
        f:close()
        os.rename(tmp_path, path)
    end
end

function _M.restore()
    local path = _M._json_path()
    local f = io.open(path, "r")
    if not f then
        return
    end
    local data = f:read("*all")
    f:close()
    -- cjson/dkjson raise on malformed JSON; a corrupt stats file must not
    -- kill init_worker — degrade to an empty slate instead.
    local ok, decoded = pcall(json.decode, data)
    if not ok or not decoded then
        return
    end
    -- Version gate: only v2 (host-nested) payloads are restored. Legacy flat
    -- { uri = {...} } files are dropped — stats are ephemeral, not config.
    if type(decoded) ~= "table" or decoded.v ~= 2 or type(decoded.data) ~= "table" then
        return
    end
    local shared = ngx.shared.statistics
    if not shared then
        return
    end
    local per_host = per_host_uri_limit()
    local max_hosts = get_max_hosts()

    for host, per_host_data in pairs(decoded.data) do
        if type(per_host_data) == "table" then
            local restored_uris = lru_list(shared, "index:all:" .. host)
            local indexed = {}
            for _, uri in ipairs(restored_uris) do
                indexed[uri] = true
            end
            for uri, entry in pairs(per_host_data) do
                local key = "all:" .. host .. ":" .. uri
                if not shared:get(key .. ":count") then
                    dict_guard.set(shared, "stats.restore", key .. ":count", entry.count or 0)
                    dict_guard.set(shared, "stats.restore", key .. ":bytes", entry.bytes or 0)
                    dict_guard.set(shared, "stats.restore", key .. ":time", entry.time or 0)
                    if entry.status then
                        for code, count in pairs(entry.status) do
                            dict_guard.set(shared, "stats.restore", key .. ":status_" .. code, count)
                        end
                    end
                end
                if not indexed[uri] and #restored_uris < per_host then
                    restored_uris[#restored_uris + 1] = uri
                    indexed[uri] = true
                end
            end
            dict_guard.set(shared, "stats.restore", "index:all:" .. host, json.encode(restored_uris))
            lru_add(shared, "hosts:all", host, max_hosts)
        end
    end
end

function _M._json_path()
    local base = require("core.config").resolve_path()
    if base:match("/$") then
        base = base:match("(.+)/$") or "/opt/verynginx"
    end
    return base .. "/configs/statistics.json"
end

return _M
