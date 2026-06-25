-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : statistics engine - time-windowed request counting, LRU index, persistence

local _M = {}
local config = require "core.config"

-- ---------------------------------------------------------------------------
-- LRU index helpers (stored in shared dict)
-- ---------------------------------------------------------------------------
local function lru_add(shared, index_key, uri, max_keys)
    local data = shared:get(index_key)
    local list = {}
    if data then
        local ok, decoded = pcall(require("dkjson").decode, data)
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
    shared:set(index_key, require("dkjson").encode(list))
end

local function lru_list(shared, index_key)
    local data = shared:get(index_key)
    if not data then
        return {}
    end
    local ok, decoded = pcall(require("dkjson").decode, data)
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
    -- Normalize numeric segments: /user/123 → /user/:id
    uri = uri:gsub("/%d+", "/:id")
    uri = uri:gsub("/[0-9a-fA-F]{%d+}", "/:hex")
    return uri
end

-- ---------------------------------------------------------------------------
-- Initialization
-- ---------------------------------------------------------------------------
function _M.init()
    local persist_interval = (config and config.statistics and config.statistics.persist_interval) or 300
    ngx.timer.every(60, function()
        _M._flush_bucket("1m", "5m")
    end)
    ngx.timer.every(300, function()
        _M._flush_bucket("5m", "1h")
    end)
    ngx.timer.every(persist_interval, function()
        _M.persist()
    end)
    -- Restore from disk on startup
    _M.restore()
end

-- ---------------------------------------------------------------------------
-- Per-request logging
-- ---------------------------------------------------------------------------
function _M.log_request(ctx)
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
    _M._record_seen_code(shared, key, code_idx)
    lru_add(shared, "index:1m", uri, max_keys)
end

local function _seen_codes_key(key)
    return key .. ":seen_codes"
end

function _M._record_seen_code(shared, key, code)
    local sk = _seen_codes_key(key)
    local codes = shared:get(sk)
    local code_str = tostring(code)
    if not codes then
        shared:set(sk, code_str)
        return
    end
    if not codes:find("," .. code_str .. ",", 1, true) and codes ~= code_str and codes:find(code_str, 1, true) ~= 1 then
        shared:set(sk, codes .. "," .. code_str)
    end
end

local function _get_seen_codes(shared, key)
    local raw = shared:get(_seen_codes_key(key))
    if not raw or raw == "" then
        return {}
    end
    local codes = {}
    for c in raw:gmatch("[^,]+") do
        codes[#codes + 1] = c
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

        if count > 0 then
            local dst_key = dst_bucket .. ":" .. uri
            shared:incr(dst_key .. ":count", count, 0)
            shared:incr(dst_key .. ":bytes", bytes, 0)
            shared:incr(dst_key .. ":time", time, 0)
            lru_add(shared, "index:" .. dst_bucket, uri, max_keys)
            -- Merge status codes (only codes that were actually recorded)
            local codes = _get_seen_codes(shared, src_key)
            for _, c in ipairs(codes) do
                local sc = shared:get(src_key .. ":status_" .. c)
                if sc and sc > 0 then
                    shared:incr(dst_key .. ":status_" .. c, sc, 0)
                    _M._record_seen_code(shared, dst_key, tonumber(c))
                end
            end
        end
        -- Clear source bucket
        shared:delete(src_key .. ":count")
        shared:delete(src_key .. ":bytes")
        shared:delete(src_key .. ":time")
        local codes = _get_seen_codes(shared, src_key)
        for _, c in ipairs(codes) do
            shared:delete(src_key .. ":status_" .. c)
        end
        shared:delete(_seen_codes_key(src_key))
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
                time = tonumber(string.format("%.3f", shared:get(key .. ":time") or 0)),
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

    return require("dkjson").encode(report)
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
        f:write(require("dkjson").encode(data, { indent = true }))
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
    local decoded = require("dkjson").decode(data)
    if not decoded then
        return
    end
    local shared = ngx.shared.statistics
    if not shared then
        return
    end
    for uri, entry in pairs(decoded) do
        local key = "all:" .. uri
        shared:set(key .. ":count", entry.count or 0)
        shared:set(key .. ":bytes", entry.bytes or 0)
        shared:set(key .. ":time", entry.time or 0)
        if entry.status then
            for code, count in pairs(entry.status) do
                shared:set(key .. ":status_" .. code, count)
                _M._record_seen_code(shared, key, tonumber(code))
            end
        end
        lru_add(shared, "index:all", uri, (config and config.statistics and config.statistics.max_uri_keys) or 10000)
    end
end

function _M._json_path()
    local base = require("core.config").resolve_path()
    if base:match("/$") then
        base = base:match("(.+)/$") or "/opt/verynginx/verynginx"
    end
    return base .. "/configs/statistics.json"
end

return _M