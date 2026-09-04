-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-25
-- @Author  : VeryNginx v2
-- @Disc    : GeoIP lookup module (MaxMind DB via lua-resty-maxminddb)

local _M = {}

local config = require "core.config"

-- Load maxminddb module lazily (may not be installed)
local maxminddb
do
    local ok, mod = pcall(require, "resty.maxminddb")
    if ok then
        maxminddb = mod
    end
end

local _db = nil
local _geodb_path = nil
-- Negative cache: once a (re)load fails (DB missing/corrupt), do not retry the
-- expensive open + WARN log on every request. The data plane calls lookup()/
-- is_available() per request; without this cooldown a missing 66MB DB means a
-- file open + a WARN per request — a hot-path collapse. After the interval we
-- retry once (e.g. the updater may have fetched the DB in the meantime).
local GEOIP_RETRY_INTERVAL = 60
local _db_failed_at = 0

local function geoip_cooldown_active()
    return _db_failed_at > 0 and (ngx.now() - _db_failed_at) < GEOIP_RETRY_INTERVAL
end

local function geoip_mark_failed()
    _db_failed_at = ngx.now()
end

local function geoip_mark_ok()
    _db_failed_at = 0
end

-- Initialize GeoIP database
function _M.init(geodb_path)
    if not maxminddb then
        return false, "lua-resty-maxminddb not installed"
    end
    _geodb_path = geodb_path
    -- Ensure parent directory exists
    pcall(function()
        local dir = _geodb_path:match("^(.-)/[^/]+$")
        if dir and dir ~= "" then
            local lfs_ok, lfs = pcall(require, "lfs")
            if lfs_ok then
                local parts = {}
                local current = dir
                while current and current ~= "" do
                    if lfs.attributes(current, "mode") == "directory" then break end
                    table.insert(parts, 1, current)
                    current = current:match("^(.-)/[^/]+$")
                end
                for _, d in ipairs(parts) do
                    lfs.mkdir(d)
                    pcall(function() lfs.chmod(d, 755) end)
                end
            end
        end
    end)
    local ok, result = pcall(maxminddb.new, maxminddb, _geodb_path)
    if not ok then
        return false, "failed to load GeoIP DB: " .. tostring(result)
    end
    if not result then
        return false, "failed to load GeoIP DB: maxminddb:new returned nil"
    end
    _db = result
    ngx.log(ngx.DEBUG, "geoip: loaded DB from ", _geodb_path)
    return true
end

-- Reload GeoIP database (after auto-update)
function _M.reload()
    if not maxminddb then return false, "maxminddb not installed" end
    local path = (_geodb_path and _geodb_path ~= "" and _geodb_path)
        or (config.geoip and config.geoip.geodb_path and config.geoip.geodb_path ~= "" and config.geoip.geodb_path)
        or ""
    if path == "" then
        geoip_mark_failed()
        return false, "no geodb_path configured"
    end
    local ok, result = pcall(maxminddb.new, maxminddb, path)
    if not ok then
        geoip_mark_failed()
        return false, "reload failed: " .. tostring(result)
    end
    if not result then
        geoip_mark_failed()
        return false, "reload failed: maxminddb:new returned nil"
    end
    _db = result
    _geodb_path = path
    geoip_mark_ok()
    return true
end

-- Get current DB path
function _M.get_geodb_path()
    return _geodb_path
end

-- Check if GeoIP is available (DB loaded in memory)
function _M.is_available()
    if _db ~= nil then
        return true
    end
    -- Negative cache: if a recent (re)load failed, skip the per-request file
    -- open + WARN storm until the cooldown elapses.
    if geoip_cooldown_active() then
        return false
    end
    -- Try reload if DB file was downloaded after startup
    local path = (_geodb_path and _geodb_path ~= "" and _geodb_path)
        or (config.geoip and config.geoip.geodb_path and config.geoip.geodb_path ~= "" and config.geoip.geodb_path)
        or ""
    if path == "" then
        ngx.log(ngx.WARN, "geoip: is_available() — no geodb_path configured")
        geoip_mark_failed()
        return false
    end
    local f = io.open(path, "rb")
    if not f then
        ngx.log(ngx.WARN, "geoip: is_available() — DB file not found at ", path)
        geoip_mark_failed()
        return false
    end
    f:close()
    ngx.log(ngx.WARN, "geoip: is_available() — DB file found, attempting reload from ", path)
    local ok, err = _M.reload()
    if ok then
        ngx.log(ngx.WARN, "geoip: is_available() — reload successful")
        return true
    end
    ngx.log(ngx.WARN, "geoip: is_available() — reload failed: ", tostring(err))
    return false
end

--- Lookup GeoIP data for an IP address.
-- @param ip string: IPv4 or IPv6 address
-- @return table|nil: { country_code, country_name, city_name, continent, latitude, longitude, asn }
function _M.lookup(ip)
    if not ip then return nil end
    -- Auto-reload if database was downloaded after startup (e.g. by updater).
    -- Respect the negative cache so a missing/corrupt DB doesn't trigger a file
    -- open + error log on every request (hot-path collapse).
    if not _db then
        if geoip_cooldown_active() then return nil end
        local ok = _M.reload()
        if not ok then return nil end
    end
    local ok, result = pcall(_db.lookup, _db, ip)
    if not ok or not result then return nil end

    local geo = {}

    -- Country
    if result.country then
        if result.country.iso_code then
            geo.country_code = result.country.iso_code
        end
        if result.country.names and result.country.names.en then
            geo.country_name = result.country.names.en
        end
    end

    -- City
    if result.city and result.city.names and result.city.names.en then
        geo.city_name = result.city.names.en
    end

    -- Continent
    if result.continent and result.continent.code then
        geo.continent = result.continent.code
    end

    -- Location
    if result.location then
        if result.location.latitude then geo.latitude = result.location.latitude end
        if result.location.longitude then geo.longitude = result.location.longitude end
    end

    -- ASN (if using GeoLite2-ASN or GeoIP2-ISP)
    if result.autonomous_system_number then
        geo.asn = result.autonomous_system_number
    end
    if result.autonomous_system_organization then
        geo.asn_org = result.autonomous_system_organization
    end

    -- Registered country (for geo-proxies)
    if result.registered_country and result.registered_country.iso_code then
        geo.registered_country = result.registered_country.iso_code
    end

    return geo
end

--- Get country code for an IP (fast lookup).
-- @param ip string
-- @return string|nil: ISO country code (e.g. "CN", "US")
function _M.country(ip)
    local geo = _M.lookup(ip)
    return geo and geo.country_code
end

--- Check if an IP belongs to a country.
-- @param ip string
-- @param country_code string: ISO 3166-1 alpha-2 (e.g. "CN")
-- @return boolean
function _M.is_country(ip, country_code)
    if not country_code then return false end
    local cc = _M.country(ip)
    return cc and cc:upper() == country_code:upper()
end

--- Get config for GeoIP blocking/allowing.
function _M.get_config()
    return config.geoip or {}
end

--- Cached lookup: returns cached geo data from ngx.ctx or calls lookup().
-- Eliminates duplicate FFI calls when both check_block and track are used.
function _M.cached_lookup(ip)
    if ngx.ctx and ngx.ctx._geoip_data then
        return ngx.ctx._geoip_data
    end
    local geo = _M.lookup(ip)
    if ngx.ctx then
        ngx.ctx._geoip_data = geo
    end
    return geo
end

--- Check if an IP should be blocked by GeoIP rules.
-- @param ip string
-- @param geo table|nil: precomputed lookup result (optional)
-- @return boolean, string: blocked, reason
function _M.check_block(ip, geo)
    local cfg = _M.get_config()
    if not cfg.enable then return false end

    geo = geo or _M.lookup(ip)
    if not geo or not geo.country_code then return false end

    local cc = geo.country_code:upper()

    -- Whitelist takes priority
    if cfg.whitelist then
        for _, c in ipairs(cfg.whitelist) do
            if c:upper() == cc then return false end
        end
    end

    -- Blocklist
    if cfg.blocklist then
        for _, c in ipairs(cfg.blocklist) do
            if c:upper() == cc then
                return true, "geoip:blocklist:" .. cc
            end
        end
    end

    -- Block by continent
    if cfg.block_continents and geo.continent then
        for _, cont in ipairs(cfg.block_continents) do
            if cont:upper() == geo.continent:upper() then
                return true, "geoip:block_continent:" .. geo.continent
            end
        end
    end

    return false
end

--- Get stats for dashboard (country hit counts).
-- @param shared ngx.shared dict to read IP->country cache from
-- @return table: { country_code -> count }
function _M.get_stats(shared_dict)
    if not shared_dict then return {} end
    local stats = {}
    local keys = shared_dict:get_keys(1000)
    for _, k in ipairs(keys) do
        if k:sub(1, 9) == "geo_ip:cc:" then
            local cc = k:sub(10)
            local count = shared_dict:get(k) or 0
            if count > 0 then
                stats[cc] = count
            end
        end
    end
    return stats
end

--- Track an IP's country in shared dict for stats.
-- @param ip string
-- @param shared_dict ngx.shared dict
-- @param geo table|nil: precomputed lookup result (optional)
function _M.track(ip, shared_dict, geo)
    if not shared_dict or not ip then return end
    local cc
    if geo then
        cc = geo.country_code
    else
        cc = _M.country(ip)
    end
    if cc then
        local key = "geo_ip:cc:" .. cc
        pcall(function() shared_dict:incr(key, 1, 0, 86400) end)
    end
end

--- Get DB file info for status display.
-- @return table: { path, size, mtime, available }
function _M.get_status()
    -- Prefer in-memory path, fall back to configured path
    local path = _geodb_path or (config.geoip and config.geoip.geodb_path) or ""
    local info = { path = path, available = false, size = 0, mtime = 0 }
    if path ~= "" then
        local f = io.open(path, "rb")
        if f then
            info.available = true
            info.size = f:seek("end")
            f:close()
            pcall(function()
                local lfs = require "lfs"
                local attr = lfs.attributes(path)
                if attr then info.mtime = attr.modification end
            end)
        end
    end
    -- Also expose whether maxminddb module is available
    info.module_available = maxminddb ~= nil
    return info
end

return _M
