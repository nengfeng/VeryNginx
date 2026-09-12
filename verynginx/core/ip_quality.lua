-- -*- coding: utf-8 -*-
-- @Date    : 2026-09-07
-- @Author  : VeryNginx v2
-- @Disc    : IP quality enrichment — ip-api.com lookup (type/ISP/ASN) with
--            shared-dict caching. See AGENTS.md section 5.

local _M = {}

local json = require "dkjson"
local dict_guard = require "core.dict_guard"
local config = require "core.config"

-- ip-api.com free tier: 45 req/min per source IP, HTTP only (no TLS on the
-- free endpoint — the queried IP is not sensitive data), all fields used
-- here (isp/org/as/reverse/mobile/proxy/hosting) are included in the free
-- response.
local API_BASE = "http://ip-api.com/json/"
local FIELDS = "status,message,continent,country,countryCode,region,regionName," ..
    "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
local CACHE_PREFIX = "ipq:"
local ERR_PREFIX = "ipq:err:"
local CACHE_TTL = 86400   -- IP metadata changes rarely; refresh daily
local ERR_TTL = 60        -- negative cache: rate limit / network failures
local HTTP_TIMEOUT = 5    -- seconds

-- Fingerprint of the currently configured enrichment keys. Cached entries
-- store it; adding/changing a key invalidates stale entries that were
-- fetched without (or with different) keys.
local function keys_fingerprint()
    local g = config.geoip or {}
    local raw = (g.abuseipdb_key or "") .. "|" .. (g.ipinfo_token or "")
    if raw == "|" then return "" end
    return ngx.md5(raw)
end

-- Enrichment keys from the live config (never cached at module scope: the
-- config hot-reloads). "(redacted)" placeholders count as absent.
local function get_keys()
    local g = config.geoip or {}
    return {
        abuseipdb = (g.abuseipdb_key and g.abuseipdb_key ~= ""
            and g.abuseipdb_key ~= "(redacted)") and g.abuseipdb_key or nil,
        ipinfo = (g.ipinfo_token and g.ipinfo_token ~= ""
            and g.ipinfo_token ~= "(redacted)") and g.ipinfo_token or nil,
    }
end

local last_abuse_warn = 0

local function shared()
    return ngx.shared.vn_config
end

-- Cheap reserved-range check so testing 192.168.x.x in the panel neither
-- burns the 45/min free quota nor leaks internal names to a third party.
-- Covers v4 private/loopback/link-local/unspecified + v6 loopback/ULA/
-- link-local and ::ffff:-mapped forms.
local function is_reserved(ip)
    local mapped = ip:lower():match("^::ffff:(%d+%.%d+%.%d+%.%d+)$")
    if mapped then ip = mapped end
    if ip:find(":", 1, true) then
        local lower = ip:lower()
        if lower == "::" or lower == "::1" then return true end
        if lower:match("^fe[89ab]") then return true end            -- link-local
        if lower:match("^f[cd]") then return true end               -- ULA fc00::/7
        return false
    end
    local a, b = ip:match("^(%d+)%.(%d+)%.")
    if not a then return false end
    a = tonumber(a); b = tonumber(b) or 0
    if a == 0 or a == 10 or a == 127 or a == 255 then return true end
    if a == 169 and b == 254 then return true end                   -- link-local
    if a == 172 and b >= 16 and b <= 31 then return true end
    if a == 192 and b == 168 then return true end
    if a == 100 and b >= 64 and b <= 127 then return true end       -- CGNAT
    return false
end

local function classify(entry)
    if entry.proxy then return "proxy" end
    if entry.hosting then return "hosting" end
    if entry.mobile then return "mobile" end
    return "residential"
end

--- Parse one ip-api.com JSON response into the normalized entry shape.
-- Returns (entry) or (nil, reason). Exported for unit tests.
function _M.parse_response(body)
    local ok, data = pcall(json.decode, body)
    if not ok or type(data) ~= "table" then
        return nil, "invalid JSON from ip-api"
    end
    if data.status ~= "success" then
        -- e.g. "private range", "reserved range", quota messages
        return nil, tostring(data.message or "query failed")
    end
    local entry = {
        source = "ip-api.com",
        queried = data.query,
        country = data.country,
        country_code = data.countryCode,
        region = data.regionName,
        city = data.city,
        zip = data.zip,
        lat = data.lat,
        lon = data.lon,
        timezone = data.timezone,
        isp = data.isp,
        org = data.org,
        as = data.as,
        asname = data.asname,
        reverse = data.reverse,
        proxy = data.proxy == true,
        hosting = data.hosting == true,
        mobile = data.mobile == true,
    }
    entry.ip_type = classify(entry)
    return entry
end

-- Fetch the raw JSON body for one IP. Exported for unit tests (the spec
-- stubs resty.http instead of this function).
--- AbuseIPDB risk enrichment (free tier: 1000 checks/day with a key).
-- @return risk table or nil + reason
local function fetch_abuse(ip, key)
    local ok_http, http = pcall(require, "resty.http")
    if not ok_http then
        return nil, "resty.http not available"
    end
    local httpc = http.new()
    httpc:set_timeout(HTTP_TIMEOUT * 1000)
    local res, err = httpc:request_uri(
        "https://api.abuseipdb.com/api/v2/check?ipAddress=" .. ip .. "&maxAgeInDays=90", {
        method = "GET",
        headers = { ["Key"] = key, ["Accept"] = "application/json" },
    })
    if not res then return nil, "request failed: " .. tostring(err) end
    if res.status == 401 or res.status == 402 then return nil, "invalid or expired AbuseIPDB key" end
    if res.status == 429 then return nil, "AbuseIPDB rate limited (free: 1000/day)" end
    if res.status ~= 200 then return nil, "HTTP " .. res.status end
    local ok, data = pcall(json.decode, res.body)
    if not ok or type(data) ~= "table" or type(data.data) ~= "table" then
        return nil, "invalid JSON from AbuseIPDB"
    end
    local d = data.data
    return {
        score = tonumber(d.abuseConfidenceScore) or 0,
        reports = tonumber(d.totalReports) or 0,
        tor = d.isTor == true,
        usage = d.usageType,
    }
end

--- ipinfo.io fallback provider (free token: 50k req/month, HTTPS) — used
--- when the ip-api call fails: rate limit, plain-HTTP blocked, etc.
-- @return base-entry fields or nil + reason
local function fetch_ipinfo(ip, token)
    local ok_http, http = pcall(require, "resty.http")
    if not ok_http then
        return nil, "resty.http not available"
    end
    local httpc = http.new()
    httpc:set_timeout(HTTP_TIMEOUT * 1000)
    local res, err = httpc:request_uri(
        "https://ipinfo.io/" .. ip .. "/json?token=" .. token, {
        method = "GET",
        headers = { ["User-Agent"] = "VeryNginx-IPQuality/1.0" },
    })
    if not res then return nil, "request failed: " .. tostring(err) end
    if res.status == 401 or res.status == 403 then return nil, "invalid ipinfo token" end
    if res.status == 429 then return nil, "ipinfo rate limited" end
    if res.status ~= 200 then return nil, "HTTP " .. res.status end
    local ok, data = pcall(json.decode, res.body)
    if not ok or type(data) ~= "table" then
        return nil, "invalid JSON from ipinfo"
    end
    if data.error then
        return nil, tostring(data.error.title or data.error.message or "ipinfo error")
    end
    -- org is "AS15169 Google LLC" - split the AS number for the panel.
    local as_num, as_name
    if data.org then
        as_num, as_name = data.org:match("^(AS%d+)%s+(.+)$")
    end
    return {
        source = "ipinfo.io",
        queried = ip,
        country_code = data.country,
        region = data.region,
        city = data.city,
        zip = data.postal,
        timezone = data.timezone,
        org = data.org,
        as = as_num or data.org,
        asname = as_name,
        reverse = data.hostname,
        -- free ipinfo has no type flags; the panel shows the unknown label
        ip_type = "unknown",
    }
end

local function fetch(ip)
    local ok_http, http = pcall(require, "resty.http")
    if not ok_http then
        return nil, "resty.http not available"
    end
    local httpc = http.new()
    httpc:set_timeout(HTTP_TIMEOUT * 1000)
    local url = API_BASE .. ip .. "?fields=" .. FIELDS
    local res, err = httpc:request_uri(url, {
        method = "GET",
        headers = { ["User-Agent"] = "VeryNginx-IPQuality/1.0" },
    })
    if not res then return nil, "request failed: " .. tostring(err) end
    if res.status == 429 then return nil, "rate limited (free tier: 45 req/min)" end
    if res.status ~= 200 then return nil, "HTTP " .. res.status end
    return res.body
end

--- Full lookup with caching.
-- Cache layout (vn_config): ipq:<ip> -> normalized entry JSON (24h);
-- ipq:err:<ip> -> last failure reason (60s negative cache, protects the
-- 45/min free quota from repeated clicks during an outage).
-- @return entry table, or nil + reason
function _M.lookup(ip)
    if type(ip) ~= "string" or ip == "" or not ip:match("^[%x%.:%[%]]+$") then
        return nil, "invalid ip"
    end

    local keys = get_keys()
    local fp = keys_fingerprint()
    local s = shared()
    if s then
        local raw = s:get(CACHE_PREFIX .. ip)
        if raw then
            local ok, entry = pcall(json.decode, raw)
            if ok and type(entry) == "table" then
                if (entry.keys_fp or "") == fp then
                    entry.cached = true
                    return entry
                end
                -- Stale: fetched with different/no enrichment keys. Fall
                -- through to a fresh fetch (the entry is replaced below).
            else
                -- Unparseable cache entry: drop it.
                s:delete(CACHE_PREFIX .. ip)
            end
        end
        local err_cached = s:get(ERR_PREFIX .. ip)
        if err_cached then
            return nil, tostring(err_cached)
        end
    end

    -- Reserved ranges: answered locally, never sent to a third party.
    if is_reserved(ip) then
        local entry = {
            source = "local",
            queried = ip,
            ip_type = "reserved",
            reserved = true,
            keys_fp = fp,
        }
        if s then
            dict_guard.set(s, "ipq", CACHE_PREFIX .. ip, json.encode(entry), 300)
        end
        return entry
    end

    -- Provider chain: ip-api (no key, type flags) -> ipinfo (token, when
    -- ip-api failed) -> AbuseIPDB risk enrichment (key, independent of the
    -- base provider).
    local entry
    local body, err = fetch(ip)
    if body then
        entry, err = _M.parse_response(body)
        if not entry and keys.ipinfo then
            entry = fetch_ipinfo(ip, keys.ipinfo)
        end
    elseif keys.ipinfo then
        entry = fetch_ipinfo(ip, keys.ipinfo)
    end
    if not entry then
        if s then dict_guard.set(s, "ipq.err", ERR_PREFIX .. ip, tostring(err), ERR_TTL) end
        return nil, err
    end
    entry.keys_fp = fp

    -- AbuseIPDB risk enrichment: independent of the base provider. A failure
    -- here degrades the entry (no risk block) instead of failing the lookup.
    if keys.abuseipdb then
        local risk, aerr = fetch_abuse(ip, keys.abuseipdb)
        if risk then
            entry.risk = risk
        else
            -- Throttle the WARN: this fires per lookup while the key/quota
            -- is broken, and repeated identical lines are noise.
            local now = ngx.now()
            if now - last_abuse_warn > 300 then
                last_abuse_warn = now
                ngx.log(ngx.WARN, "ip_quality: AbuseIPDB enrichment failed: ", tostring(aerr))
            end
        end
    end

    if s then
        dict_guard.set(s, "ipq", CACHE_PREFIX .. ip, json.encode(entry), CACHE_TTL)
    end
    return entry
end

return _M
