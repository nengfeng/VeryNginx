-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-25
-- @Author  : VeryNginx v2
-- @Disc    : GeoIP database auto-updater — periodic download + atomic replace

local _M = {}

local geoip = require "core.geoip"
local audit = require "core.audit"
local config = require "core.config"

local SHARED_DICT = "vn_config"
local LOCK_KEY = "geoip_update_lock"
local ETAG_KEY = "geoip_remote_etag"
local LAST_CHECK_KEY = "geoip_last_check"
local LAST_UPDATE_KEY = "geoip_last_update"

-- Validate MMDB file magic bytes
local function validate_mmdb(path)
    local f = io.open(path, "rb")
    if not f then return false, "cannot open file" end
    local magic = f:read(12)
    f:close()
    if not magic or #magic < 12 then return false, "file too small" end
    -- MaxMind DB magic: 0xAB 0xCD 0xEF "MaxMind.com"
    local a, b, c = magic:byte(1, 3)
    if a ~= 0xAB or b ~= 0xCD or c ~= 0xEF then
        return false, "invalid MMDB magic"
    end
    return true
end

-- Check if required modules are available
local function check_deps()
    local ok_http, http = pcall(require, "resty.http")
    if ok_http then
        return true, http
    end
    -- Fallback: check if curl CLI is available
    local handle = io.popen("which curl 2>/dev/null")
    local curl_path = handle:read("*a"):gsub("%s+", "")
    handle:close()
    if curl_path ~= "" then
        return true, nil -- nil means use curl CLI
    end
    return false, "neither lua-resty-http nor curl CLI is available"
end

-- Download file from URL to destination
local function download_file(url, dest, timeout)
    timeout = timeout or 30
    -- Try resty.http first
    local ok_http, http = pcall(require, "resty.http")
    if ok_http then
        local httpc = http.new()
        httpc:set_timeout(timeout * 1000)
        local res, err = httpc:request_uri(url, {
            method = "GET",
            headers = { ["User-Agent"] = "VeryNginx-GeoIP-Updater/2.0" },
        })
        if not res then return false, "download failed: " .. tostring(err) end
        if res.status ~= 200 then return false, "HTTP " .. res.status end
        local f, ferr = io.open(dest, "wb")
        if not f then return false, "cannot write: " .. tostring(ferr) end
        f:write(res.body)
        f:close()
        return true
    end
    -- Fallback: use curl CLI
    local cmd = string.format('curl -fsSL --max-time %d -A "VeryNginx-GeoIP-Updater/2.0" -o %s %s 2>&1',
        timeout, dest, url)
    local handle = io.popen(cmd)
    local output = handle:read("*a") or ""
    local ok, _, exit_code = handle:close()
    if not ok and (exit_code or 0) ~= 0 then
        return false, "curl failed: " .. output:sub(0, 200)
    end
    return true
end

-- Get remote ETag via HEAD request
local function get_remote_etag(url)
    -- Try resty.http first
    local ok_http, http = pcall(require, "resty.http")
    if ok_http then
        local httpc = http.new()
        httpc:set_timeout(10000)
        local res, err = httpc:request_uri(url, { method = "HEAD" })
        if not res then return nil, tostring(err) end
        return res.headers["ETag"] or res.headers["Last-Modified"]
    end
    -- Fallback: use curl CLI
    local handle = io.popen(string.format('curl -fsSI --max-time 10 %s 2>&1', url))
    local output = handle:read("*a") or ""
    handle:close()
    local etag = output:match("ETag:[%s]*(.-)\r?\n")
    if etag and etag ~= "" then return etag end
    return output:match("Last%-Modified:[%s]*(.-)\r?\n")
end

