-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-25
-- @Author  : VeryNginx v2
-- @Disc    : GeoIP database auto-updater — periodic download + atomic replace

local _M = {}

local geoip = require "core.geoip"
local audit = require "core.audit"
local config = require "core.config"

local SHARED_DICT = "vn_config"
local DEFAULT_DB_PATH = "/opt/verynginx/geoip/GeoLite2-City.mmdb"
local LOCK_KEY = "geoip_update_lock"
local ETAG_KEY = "geoip_remote_etag"
local LAST_CHECK_KEY = "geoip_last_check"
local LAST_UPDATE_KEY = "geoip_last_update"

-- Community mirrors that host GeoLite2-City.mmdb (no API key required)
-- Ordered by region accessibility: China-first, then global
-- Loyalsoldier/geoip provides Country.mmdb with country+continent data
local MIRRORS = {
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb",
    "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb",
}

-- Validate MMDB file magic bytes
local function validate_mmdb(path)
    local f = io.open(path, "rb")
    if not f then return false, "cannot open file" end
    local magic = f:read(12)
    local size = f:seek("end")
    f:close()
    if not magic or #magic < 12 then return false, "file too small" end
    if size < 1024 then return false, "file too small (" .. size .. " bytes), likely download failed" end
    local a, b, c = magic:byte(1, 3)
    if a ~= 0xAB or b ~= 0xCD or c ~= 0xEF then
        return false, "invalid MMDB magic"
    end
    return true
end

-- Download file from URL (resty.http or curl CLI fallback)
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
    -- Fallback: curl CLI
    local cmd = string.format("curl -fsSL --max-time %d -A 'VeryNginx-GeoIP-Updater/2.0' -o '%s' '%s' 2>&1",
        timeout, dest, url)
    local handle = io.popen(cmd)
    local output = handle:read("*a") or ""
    local ok, _, exit_code = handle:close()
    -- Verify file was actually written (handle:close may not report exit code correctly in OpenResty)
    local check = io.open(dest, "rb")
    if not check then
        return false, "curl did not create file: " .. tostring(output):sub(0, 200)
    end
    check:close()
    if not ok and (exit_code or 0) ~= 0 then
        return false, "curl failed: " .. tostring(output):sub(0, 200)
    end
    return true
end

-- Get remote ETag via HEAD request
local function get_remote_etag(url)
    local ok_http, http = pcall(require, "resty.http")
    if ok_http then
        local httpc = http.new()
        httpc:set_timeout(10000)
        local res, err = httpc:request_uri(url, { method = "HEAD" })
        if not res then return nil, tostring(err) end
        return res.headers["ETag"] or res.headers["Last-Modified"]
    end
    -- Fallback: curl
    local handle = io.popen(string.format("curl -fsSI --max-time 10 '%s' 2>&1", url))
    local output = handle:read("*a") or ""
    handle:close()
    local etag = output:match("ETag:[%s]*(.-)\r?\n")
    if etag and etag ~= "" then return etag end
    return output:match("Last%-Modified:[%s]*(.-)\r?\n")
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
        db_path = (cfg.db_path ~= "" and cfg.db_path) or DEFAULT_DB_PATH,
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

-- Resolve download URL from config
local function resolve_url(ucfg, mirror_index)
    -- User-configured URL takes priority
    if ucfg.cdn_url and ucfg.cdn_url ~= "" then
        return ucfg.cdn_url
    end
    if ucfg.update_url and ucfg.update_url ~= "" then
        return ucfg.update_url
    end
    -- Try community mirrors
    if mirror_index and mirror_index > 0 and mirror_index <= #MIRRORS then
        return MIRRORS[mirror_index]
    end
    return MIRRORS[1]
end

-- Perform update check and download
function _M.check_update(force)
    -- Pre-flight: deps check
    local ok_deps, deps_err = pcall(require, "resty.http")
    if not ok_deps then
        local handle = io.popen("which curl 2>/dev/null")
        local curl_path = handle:read("*a"):gsub("%s+", "")
        handle:close()
        if curl_path == "" then
            return false, "neither lua-resty-http nor curl available: " .. tostring(deps_err), 500
        end
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
        local db_path = ucfg.db_path

        -- Ensure parent directory exists
        local dir = db_path:match("^(.+)/[^/]+$") or ""
        if dir ~= "" then
            os.execute("mkdir -p '" .. dir .. "' 2>/dev/null")
        end

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
            local tmp_path = db_path .. ".tmp"
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
            local rename_ok, rename_err = os.rename(tmp_path, db_path)
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
        db_path = ucfg.db_path,
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
