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
    local a, b, c = magic:byte(1, 3)
    if a ~= 0xAB or b ~= 0xCD or c ~= 0xEF then
        return false, "invalid MMDB magic"
    end
    return true
end

-- Check if required modules are available
local function check_deps()
    local ok_http, http = pcall(require, "resty.http")
    if ok_http then return true, http end
    local handle = io.popen("which curl 2>/dev/null")
    local curl_path = handle:read("*a"):gsub("%s+", "")
    handle:close()
    if curl_path ~= "" then return true, nil end
    return false, "neither lua-resty-http nor curl CLI is available"
end

-- Download file from URL to destination (resty.http or curl CLI fallback)
local function download_file(url, dest, timeout)
    timeout = timeout or 30
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
    local cmd = string.format("curl -fsSL --max-time %d -A 'VeryNginx-GeoIP-Updater/2.0' -o %s %s 2>&1",
        timeout, dest, url)
    local handle = io.popen(cmd)
    local output = handle:read("*a") or ""
    local ok, _, exit_code = handle:close()
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
    local handle = io.popen(string.format("curl -fsSI --max-time 10 %s 2>&1", url))
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
    return (ngx.time() - last_check) >= (interval_hours * 3600)
end

-- Perform update check and download
function _M.check_update(force)
    -- Pre-flight
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

    local result = pcall(function()
        local url = ucfg.use_cdn and ucfg.cdn_url or ucfg.update_url

        -- Check remote ETag
        local remote_etag = get_remote_etag(url)
        if shared and remote_etag then
            local local_etag = shared:get(ETAG_KEY)
            if local_etag and local_etag == remote_etag then
                return false, "already up to date", 200
            end
        end

        -- Download to temp file
        local tmp_path = ucfg.db_path .. ".tmp"
        local dl_ok, dl_err = download_file(url, tmp_path)
        if not dl_ok then return false, dl_err, 502 end

        -- Validate
        local valid, valid_err = validate_mmdb(tmp_path)
        if not valid then
            os.remove(tmp_path)
            return false, valid_err, 502
        end

        -- Atomic replace
        local rename_ok, rename_err = os.rename(tmp_path, ucfg.db_path)
        if not rename_ok then
            os.remove(tmp_path)
            return false, "rename failed: " .. tostring(rename_err), 500
        end

        -- Reload DB
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

    if result then
        -- pcall returns ok, err, status when the function returns 3 values
        -- Actually pcall returns ok, then the return values
        return result, "", 500
    end

    -- If pcall succeeded, it returns true plus the function's return values
    -- pcall returns: ok, result1, result2, result3, ...
    -- But Lua multiple return values: we need to capture them
    -- Actually the function inside pcall returns 3 values
    -- pcall returns: true, val1, val2, val3
    -- So 'result' will be true, and we need to capture the rest
    -- Let me restructure this
    return _M._handle_pcall(result, nil)
end

-- Handle pcall result for 3-value returns
function _M._handle_pcall(ok, ...)
    if not ok then
        return false, tostring(select(1, ...)), 500
    end
    -- ok is true, then ... has the return values
    local r1, r2, r3 = ...
    return r1 or false, tostring(r2 or ""), r3 or 200
end
