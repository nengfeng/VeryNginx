-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : statistics engine - time-windowed request counting, LRU index, persistence

local _M = {}
local config = require "core.config"
local json = pcall(require, "cjson") and require("cjson") or require("dkjson")

-- Log request sample rate: 1-in-10 requests update shdict stats
local LOG_SAMPLE_RATE = 10
local _common_codes = { "200", "301", "302", "304", "400", "401", "403", "404", "405", "500", "502", "503" }

-- ---------------------------------------------------------------------------
-- LRU index helpers (stored in shared dict)
-- ---------------------------------------------------------------------------
local function lru_add(shared, index_key, uri, max_keys)
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
        if list[i] == uri then
            table.remove(list, i)
        end
    end
    -- Add to front
    table.insert(list, 1, uri)
    -- Trim to max
    while #list > max_keys do
        table.remove(list)
    end
    shared:set(index_key, json.encode(list))
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

    local shared = ngx.shared.statistics
    if not shared then
        return
    end

    local max_keys = (config and config.statistics and config.statistics.max_uri_keys) or 10000
    local key = "1m:" .. uri
    shared:incr(key .. ":count", 1, 0)
    shared:incr(key .. ":bytes", bytes, 0)
    shared:incr(key .. ":time", time, 0)
    local code_idx = status
    shared:incr(key .. ":status_" .. code_idx, 1, 0)
    -- Update LRU index on sampled requests
    lru_add(shared, "index:1m", uri, max_keys)
end

-- ---------------------------------------------------------------------------
-- get_top_paths  — return the top-N URIs by request count
-- ---------------------------------------------------------------------------
function _M.get_top_paths(limit)
    local shared = ngx.shared.statistics
    if not shared then return {} end
    local uris = lru_list(shared, "index:1m")
    local results = {}
    for _, uri in ipairs(uris) do
        local key = "1m:" .. uri
        local count = tonumber(shared:get(key .. ":count") or 0)
        local bytes = tonumber(shared:get(key .. ":bytes") or 0)
        local time = tonumber(shared:get(key .. ":time") or 0)
        if count > 0 then
            results[#results + 1] = { uri = uri, count = count, bytes = bytes, time = time }
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

-- ---------------------------------------------------------------------------
-- Bucket flushing
-- ---------------------------------------------------------------------------
function _M._flush_bucket(src_bucket, dst_bucket)
    local shared = ngx.shared.statistics
    if not shared then
        return
    end
    local uris = lru_list(shared, "index:" .. src_bucket)
    local max_keys = (config and config.statistics and config.statistics.max_uri_keys) or 10000

    for _, uri in ipairs(uris) do
        local src_key = src_bucket .. ":" .. uri
        local count = shared:get(src_key .. ":count") or 0
        local bytes = shared:get(src_key .. ":bytes") or 0
        local time = shared:get(src_key .. ":time") or 0
        local codes = _get_seen_codes(shared, src_key)

        if count > 0 then
            local dst_key = dst_bucket .. ":" .. uri
            shared:incr(dst_key .. ":count", count, 0)
            shared:incr(dst_key .. ":bytes", bytes, 0)
            shared:incr(dst_key .. ":time", time, 0)
            lru_add(shared, "index:" .. dst_bucket, uri, max_keys)
            -- Merge status codes (only codes that were actually recorded)
            for _, c in ipairs(codes) do
                local sc = shared:get(src_key .. ":status_" .. c)
                if sc and sc > 0 then
                    shared:incr(dst_key .. ":status_" .. c, sc, 0)
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
    shared:delete("index:" .. src_bucket)
end

-- ---------------------------------------------------------------------------
-- Report generation
-- ---------------------------------------------------------------------------
function _M.report(period)
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

    local uris = lru_list(shared, "index:" .. bucket)
    local report = {}

    for _, uri in ipairs(uris) do
        local key = bucket .. ":" .. uri
        local count = shared:get(key .. ":count") or 0
        if count > 0 then
            local entry = {
                count = count,
                bytes = shared:get(key .. ":bytes") or 0,
                time = math.floor(((shared:get(key .. ":time") or 0) * 1000) + 0.5) / 1000,
                status = {},
            }
            local codes = _get_seen_codes(shared, key)
            for _, c in ipairs(codes) do
                local sc = shared:get(key .. ":status_" .. c)
                if sc and sc > 0 then
                    entry.status[c] = sc
                end
            end
            report[uri] = entry
        end
    end

    return json.encode(report)
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
    local uris = lru_list(shared, "index:all")

    local data = {}
    for _, uri in ipairs(uris) do
        local key = "all:" .. uri
        local count = shared:get(key .. ":count") or 0
        if count > 0 then
            local entry = {
                count = count,
                bytes = shared:get(key .. ":bytes") or 0,
                time = shared:get(key .. ":time") or 0,
            }
            local codes = _get_seen_codes(shared, key)
            for _, c in ipairs(codes) do
                local sc = shared:get(key .. ":status_" .. c)
                if sc and sc > 0 then
                    if not entry.status then
                        entry.status = {}
                    end
                    entry.status[c] = sc
                end
            end
            data[uri] = entry
        end
    end

    -- Atomic write via tmp + rename
    local tmp_path = path .. ".tmp"
    local f = io.open(tmp_path, "w")
    if f then
        f:write(json.encode(data, { indent = true }))
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
    local decoded = json.decode(data)
    if not decoded then
        return
    end
    local shared = ngx.shared.statistics
    if not shared then
        return
    end
    local max_keys = (config and config.statistics and config.statistics.max_uri_keys) or 10000
    local restored_uris = lru_list(shared, "index:all")
    local indexed = {}
    for _, uri in ipairs(restored_uris) do
        indexed[uri] = true
    end
    for uri, entry in pairs(decoded) do
        local key = "all:" .. uri
        if not shared:get(key .. ":count") then
            shared:set(key .. ":count", entry.count or 0)
            shared:set(key .. ":bytes", entry.bytes or 0)
            shared:set(key .. ":time", entry.time or 0)
            if entry.status then
                for code, count in pairs(entry.status) do
                    shared:set(key .. ":status_" .. code, count)
                end
            end
        end
        if not indexed[uri] and #restored_uris < max_keys then
            restored_uris[#restored_uris + 1] = uri
            indexed[uri] = true
        end
    end
    shared:set("index:all", json.encode(restored_uris))
end

function _M._json_path()
    local base = require("core.config").resolve_path()
    if base:match("/$") then
        base = base:match("(.+)/$") or "/opt/verynginx"
    end
    return base .. "/configs/statistics.json"
end

return _M