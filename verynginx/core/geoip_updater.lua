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
    if not ok_http then
        return false, "lua-resty-http not installed: " .. tostring(http)
    end
    return true, http
end

-- Download file from URL to destination
local function download_file(url, dest, timeout)
    timeout = timeout or 30
    local httpc = require "resty.http".new()
    httpc:set_timeout(timeout * 1000)

    local res, err = httpc:request_uri(url, {
        method = "GET",
        headers = {
            ["User-Agent"] = "VeryNginx-GeoIP-Updater/2.0",
        },
    })
    if not res then return false, "download failed: " .. tostring(err) end
    if res.status ~= 200 then return false, "HTTP " .. res.status end

    local f, ferr = io.open(dest, "wb")
    if not f then return false, "cannot write: " .. tostring(ferr) end
    f:write(res.body)
    f:close()
    return true
end

-- Check remote ETag via HEAD request
local function get_remote_etag(url)
    local httpc = require "resty.http".new()
    httpc:set_timeout(10000)
    local res, err = httpc:request_uri(url, { method = "HEAD" })
    if not res then return nil, tostring(err) end
    return res.headers["ETag"] or res.headers["Last-Modified"]
end

-- Acquire update lock (prevent concurrent updates)
local function acquire_lock(ttl)
    local shared = ngx.shared[SHARED_DICT]
    if not shared then return true end -- no lock available, proceed
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
        auto_update = cfg.auto_update ~= false,  -- default true
        interval_hours = cfg.update_interval_hours or 168,
        license_key = cfg.license_key or "",
        update_url = cfg.update_url or "https://download.maxmind.com/app/geoip_download",
        cdn_url = cfg.cdn_url or "https://cdn.jsdelivr.net/npm/geolite2-city@latest/GeoLite2-City.mmdb",
        use_cdn = cfg.use_cdn == true,
        db_path = cfg.db_path or "/opt/verynginx/geoip/GeoLite2-City.mmdb",
    }
end

-- Check if update is due
local function is_update_due(interval_hours, force)
    if force then return true end
    local shared = ngx.shared[SHARED_DICT]
    if not shared then return true end
    local last_check = tonumber(shared:get(LAST_CHECK_KEY) or 0)
    local now = ngx.time()
    return (now - last_check) >= (interval_hours * 3600)
end

-- Perform update check and download
function _M.check_update(force)
    -- Pre-flight checks
    local deps_ok, deps_err = check_deps()
    if not deps_ok then return false, deps_err, 500 end

    local ucfg = get_update_config()
    if not ucfg.auto_update then return false, "auto_update disabled" end
    if not is_update_due(ucfg.interval_hours, force) then return false, "not due yet" end

    -- Update last check time
    local shared = ngx.shared[SHARED_DICT]
    if shared then shared:set(LAST_CHECK_KEY, ngx.time()) end

    -- Acquire lock
    if not acquire_lock() then return false, "update already in progress" end

    local ok, err = pcall(function()
        -- Determine download URL
        local url = ucfg.use_cdn and ucfg.cdn_url or ucfg.update_url

        -- Check remote ETag
        local remote_etag = get_remote_etag(url)
        if shared and remote_etag then
            local local_etag = shared:get(ETAG_KEY)
            if local_etag and local_etag == remote_etag then
                return false, "already up to date"
            end
        end

        -- Download to temp file
        local tmp_path = ucfg.db_path .. ".tmp"
        local dl_ok, dl_err = download_file(url, tmp_path)
        if not dl_ok then
            -- Fallback to alternative URL
            local fallback_url = ucfg.use_cdn and ucfg.update_url or ucfg.cdn_url
            if fallback_url ~= url then
                dl_ok, dl_err = download_file(fallback_url, tmp_path)
                url = fallback_url
            end
        end
        if not dl_ok then return false, dl_err end

        -- Validate downloaded file
        local valid, valid_err = validate_mmdb(tmp_path)
        if not valid then
            os.remove(tmp_path)
            return false, valid_err
        end

        -- Atomic replace
        local rename_ok, rename_err = os.rename(tmp_path, ucfg.db_path)
        if not rename_ok then
            os.remove(tmp_path)
            return false, "rename failed: " .. tostring(rename_err)
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
        return true, "updated successfully", 200
    end)

    release_lock()

    if not ok then
        ngx.log(ngx.ERR, "geoip update error: ", tostring(err))
        return false, tostring(err), 500
    end
    return ok, err, 200
end

-- Get updater status
function _M.get_status()
    local ucfg = get_update_config()
    local shared = ngx.shared[SHARED_DICT]
    local status = {
        auto_update = ucfg.auto_update,
        interval_hours = ucfg.interval_hours,
        use_cdn = ucfg.use_cdn,
        db_path = ucfg.db_path,
        last_check = tonumber(shared:get(LAST_CHECK_KEY) or 0),
        last_update = tonumber(shared:get(LAST_UPDATE_KEY) or 0),
        remote_etag = shared:get(ETAG_KEY) or "",
    }
    -- Merge with DB file info
    local db_info = geoip.get_status()
    for k, v in pairs(db_info) do status[k] = v end
    return status
end

-- Initialize auto-update timer
function _M.init()
    local ucfg = get_update_config()
    if not ucfg.auto_update then return end

    -- Only worker 0 runs the timer
    if ngx.worker.id() ~= 0 then return end

    local interval = math.max(ucfg.interval_hours * 3600, 3600) -- min 1 hour
    local ok, err = ngx.timer.every(interval, function()
        _M.check_update()
    end)
    if not ok then
        ngx.log(ngx.ERR, "geoip_updater: failed to start timer: ", err)
    end
end

return _M
