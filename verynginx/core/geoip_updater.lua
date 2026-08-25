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

-- Ensure a directory exists, creating all parent directories as needed
-- Uses lfs.mkdir (Lua-native) for reliability in nginx worker context
local function ensure_dir(path)
    if not path or path == "" then return end
    local lfs_ok, lfs = pcall(require, "lfs")
    if not lfs_ok then
        ngx.log(ngx.ERR, "geoip_updater: lfs required for directory operations")
        return
    end
    -- Build list of directories to create (bottom-up)
    local parts = {}
    local current = path
    while current and current ~= "" do
        if lfs.attributes(current, "mode") == "directory" then break end
        table.insert(parts, 1, current)
        current = current:match("^(.-)/[^/]+$")
    end
    for _, d in ipairs(parts) do
        lfs.mkdir(d)
        -- Restrict to owner-write + world-readable (no group/other write).
        pcall(function() lfs.chmod(d, 755) end)
    end
end

-- Community mirrors that host MMDB-compatible files (no API key required)
-- Ordered by speed/accessibility from testing
-- P3TERX provides official MaxMind GeoLite2-City database (full coverage, ~66MB)
-- Loyalsoldier provides community Country database (v2ray routing, ~10MB)
-- GitHub raw URLs are served via Fastly CDN (global edge nodes)
local MIRRORS = {
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb",
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb",
    "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb",
}

-- Validate MMDB file (magic bytes at end of file in metadata section)
local function validate_mmdb(path)
    local f = io.open(path, "rb")
    if not f then return false, "cannot open file" end
    local size = f:seek("end")
    if size < 1024 then
        f:close()
        return false, "file too small (" .. size .. " bytes)"
    end
    -- Read last 1KB to find MMDB magic marker \xAB\xCD\xEF followed by "MaxMind"
    local scan_size = math.min(size, 1024)
    f:seek("set", size - scan_size)
    local tail = f:read(scan_size)
    f:close()
    if not tail then return false, "cannot read file tail" end
    local idx = tail:find("\xAB\xCD\xEFMaxMind", 1, true)
    if not idx then
        return false, "invalid MMDB magic (no \\xAB\\xCD\\xEFMaxMind marker found)"
    end
    return true
end

-- Download file from URL (resty.http only — curl fallback removed to prevent command injection)
local function download_file(url, dest, timeout)
    timeout = timeout or 30
    -- Ensure parent directory exists
    ensure_dir(dest:match("^(.-)/[^/]+$"))
    local ok_http, http = pcall(require, "resty.http")
    if not ok_http then
        return false, "resty.http not available (required for secure download)"
    end
    local httpc = http.new()
    httpc:set_timeout(timeout * 1000)
    -- TLS verification stays ON by default; config.geoip.tls_verify=false is
    -- an explicit operator escape hatch (no CA bundle on the box). Note the
    -- library cannot take a CA path — verification uses the worker process
    -- OpenSSL default store, which install-lnmp.sh wires up by injecting
    -- `env SSL_CERT_FILE=<bundle>;` into nginx.conf.
    local cfg_ok, cfg_mod = pcall(require, "core.config")
    local tls_verify = true
    if cfg_ok and cfg_mod and cfg_mod.geoip and cfg_mod.geoip.tls_verify == false then
        tls_verify = false
    end
    local res, err = httpc:request_uri(url, {
        method = "GET",
        ssl_verify = tls_verify,
        headers = { ["User-Agent"] = "VeryNginx-GeoIP-Updater/2.0" },
    })
    if not res then return false, "download failed: " .. tostring(err) end
    if res.status ~= 200 then return false, "HTTP " .. res.status end
    local f, ferr = io.open(dest, "wb")
    if not f then return false, "cannot write: " .. tostring(ferr) end
    f:write(res.body)
    f:close()
    -- Use lfs.chmod instead of shell command
    pcall(function() require("lfs").chmod(dest, 644) end)
    return true
end

-- Get remote ETag via HEAD request (resty.http only)
local function get_remote_etag(url)
    local ok_http, http = pcall(require, "resty.http")
    if not ok_http then
        return nil, "resty.http not available (required for secure HEAD request)"
    end
    local httpc = http.new()
    httpc:set_timeout(10000)
    -- Same TLS policy as download_file: verify unless geoip.tls_verify=false
    local cfg_ok, cfg_mod = pcall(require, "core.config")
    local tls_verify = true
    if cfg_ok and cfg_mod and cfg_mod.geoip and cfg_mod.geoip.tls_verify == false then
        tls_verify = false
    end
    local res, err = httpc:request_uri(url, {
        method = "HEAD",
        ssl_verify = tls_verify,
    })
    if not res then return nil, tostring(err) end
    return res.headers["ETag"] or res.headers["Last-Modified"]
end

-- Acquire update lock
local function acquire_lock(ttl)
    local shared = ngx.shared[SHARED_DICT]
    if not shared then return true end
    local ok, _ = shared:add(LOCK_KEY, ngx.time(), ttl or 300)
    return ok
end

-- Release update lock
local function release_lock()
    local shared = ngx.shared[SHARED_DICT]
    if shared then shared:delete(LOCK_KEY) end
end

-- Get update configuration
local function get_update_config()
    local cfg = config.geoip or {}
    return {
        auto_update = cfg.auto_update ~= false,
        interval_hours = cfg.update_interval_hours or 168,
        update_url = cfg.update_url,
        cdn_url = cfg.cdn_url,
        use_cdn = cfg.use_cdn == true,
        geodb_path = cfg.geodb_path,
    }
end

-- Check if update is due
local function is_update_due(interval_hours, force)
    if force then return true end
    local shared = ngx.shared[SHARED_DICT]
    if not shared then return true end
    local last_check = tonumber(shared:get(LAST_CHECK_KEY) or 0)
    return (ngx.time() - last_check) >= (interval_hours * 3600)
end

-- Perform update check and download
function _M.check_update(force)
    -- Pre-flight: deps check
    local ok_deps, deps_err = pcall(require, "resty.http")
    if not ok_deps then
        return false, "lua-resty-http not available: " .. tostring(deps_err), 500
    end

    local ucfg = get_update_config()
    if not ucfg.auto_update then return false, "auto_update disabled" end
    if not is_update_due(ucfg.interval_hours, force) then return false, "not due yet" end

    -- Update last check time
    local shared = ngx.shared[SHARED_DICT]
    if shared then shared:set(LAST_CHECK_KEY, ngx.time()) end

    -- Acquire lock
    if not acquire_lock() then return false, "update already in progress" end

    -- Run update logic, capture all return values
    local results = { pcall(function()
        local geodb_path = ucfg.geodb_path

        -- Ensure parent directory exists
        ensure_dir(geodb_path:match("^(.-)/[^/]+$"))

        -- Try each URL (user-configured first, then mirrors)
        local urls = {}
        if ucfg.cdn_url and ucfg.cdn_url ~= "" then
            table.insert(urls, ucfg.cdn_url)
        elseif ucfg.update_url and ucfg.update_url ~= "" then
            table.insert(urls, ucfg.update_url)
        else
            for _, m in ipairs(MIRRORS) do
                table.insert(urls, m)
            end
        end

        local last_err = "no URLs configured"
        local success = false
        local result_msg = ""
        local result_status = 502
        for i, url in ipairs(urls) do
            -- Check remote ETag
            local remote_etag = get_remote_etag(url)
            if shared and remote_etag then
                local local_etag = shared:get(ETAG_KEY)
                if local_etag and local_etag == remote_etag then
                    result_msg = "already up to date"
                    result_status = 200
                    break
                end
            end

            -- Download to temp file
            local tmp_path = geodb_path .. ".tmp"
            local dl_ok, dl_err = download_file(url, tmp_path)
            if not dl_ok then
                last_err = "mirror " .. i .. " (" .. url .. "): " .. dl_err
                ngx.log(ngx.WARN, "geoip: ", last_err)
                goto next_mirror
            end

            -- Validate MMDB magic
            local valid, valid_err = validate_mmdb(tmp_path)
            if not valid then
                os.remove(tmp_path)
                last_err = "mirror " .. i .. " invalid file: " .. valid_err
                ngx.log(ngx.WARN, "geoip: ", last_err)
                goto next_mirror
            end

            -- Atomic replace
            local rename_ok, rename_err = os.rename(tmp_path, geodb_path)
            if not rename_ok then
                os.remove(tmp_path)
                last_err = "rename failed: " .. tostring(rename_err)
                ngx.log(ngx.WARN, "geoip: ", last_err)
                goto next_mirror
            end

            -- Reload GeoIP DB
            local reload_ok, reload_err = geoip.reload()
            if not reload_ok then
                ngx.log(ngx.WARN, "geoip: DB replaced but reload failed: ", reload_err)
            end

            -- Update tracking
            if shared then
                shared:set(ETAG_KEY, remote_etag or "")
                shared:set(LAST_UPDATE_KEY, ngx.time())
            end

            audit.log("geoip_auto_updated", "url=" .. url, "-")
            success = true
            result_msg = "updated successfully from mirror " .. i
            result_status = 200
            do break end -- break must be last statement; wrap in do/end block

            ::next_mirror::
        end

        if success then
            return true, result_msg, result_status
        end
        return false, (result_msg ~= "" and result_msg) or ("all mirrors failed: " .. last_err), result_status
    end) }

    release_lock()

    -- Parse pcall results: { ok, val1, val2, val3, ... }
    local ok = table.remove(results, 1) -- first element is pcall success flag
    if not ok then
        -- pcall caught an error; results[1] is the error message
        return false, tostring(results[1] or "unknown error"), 500
    end
    -- pcall succeeded; results contains the inner function's return values
    local success = results[1]
    local message = results[2]
    local status = results[3]
    return success or false, tostring(message or ""), status or 200
end

-- Get updater status
function _M.get_status()
    local ucfg = get_update_config()
    local shared = ngx.shared[SHARED_DICT] or {}
    local status = {
        auto_update = ucfg.auto_update,
        interval_hours = ucfg.interval_hours,
        use_cdn = ucfg.use_cdn,
        geodb_path = ucfg.geodb_path,
        last_check = tonumber(shared:get(LAST_CHECK_KEY) or 0),
        last_update = tonumber(shared:get(LAST_UPDATE_KEY) or 0),
        remote_etag = shared:get(ETAG_KEY) or "",
    }
    -- Merge with DB file info (path, available, size, mtime)
    local db_info = geoip.get_status()
    for k, v in pairs(db_info) do status[k] = v end
    return status
end

-- Initialize auto-update timer (worker 0 only)
function _M.init()
    local ucfg = get_update_config()
    if not ucfg.auto_update then return end
    if ngx.worker.id() ~= 0 then return end

    local interval = math.max(ucfg.interval_hours * 3600, 3600)
    local ok, err = ngx.timer.every(interval, function()
        _M.check_update(false)
    end)
    if not ok then
        ngx.log(ngx.ERR, "geoip_updater: failed to start timer: ", err)
    end
end

return _M
