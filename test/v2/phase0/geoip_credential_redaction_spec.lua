-- -*- coding: utf-8 -*-
-- P2-6: GeoIP credential redaction + save() sentinel backfill.
--
-- GET /config, GET /config/export and GET /geoip/config must not echo live
-- credentials (license_key, abuseipdb_key, ipinfo_token) to API consumers.
-- They are replaced with the "(redacted)" sentinel; core.config.save()
-- backfills the real value when the sentinel comes back unchanged, so a
-- dashboard read-modify-save cycle never destroys a stored key.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

local function ensure_ngx()
    if not _G.ngx then _G.ngx = {} end
    local ngx = _G.ngx
    function ngx.log() end
    ngx.WARN = 6; ngx.ERR = 5
    ngx.time = function() return 1700000000 end
    ngx.md5 = function(s) return "x" end
    ngx.random_bytes = function(n) return string.rep("R", n) end
    ngx.shared = setmetatable({}, {
        __index = function(_, name)
            ngx._stores = ngx._stores or {}
            ngx._expires = ngx._expires or {}
            if not ngx._stores[name] then ngx._stores[name] = {} end
            if not ngx._expires[name] then ngx._expires[name] = {} end
            local st = ngx._stores[name]
            local ex = ngx._expires[name]
            return {
                get = function(_, key)
                    if ex[key] and ngx.time() > ex[key] then
                        st[key] = nil; ex[key] = nil
                    end
                    return st[key]
                end,
                set = function(_, key, val, ttl)
                    st[key] = val
                    if ttl then ex[key] = ngx.time() + ttl end
                    return true
                end,
                add = function(_, key, val, ttl)
                    if ex[key] and ngx.time() > ex[key] then
                        st[key] = nil; ex[key] = nil
                    end
                    if st[key] then return false end
                    st[key] = val
                    if ttl then ex[key] = ngx.time() + ttl end
                    return true
                end,
                delete = function(_, key) st[key] = nil; ex[key] = nil end,
                expire = function(_, key, ttl)
                    if ttl then ex[key] = ngx.time() + ttl end
                end,
            }
        end,
    })
end
ensure_ngx()

local helpers = require "api.helpers"

describe("api.helpers.redact_geoip_credentials", function()
    it("redacts all three credential fields when set", function()
        local section = {
            license_key = "mm-live-1",
            abuseipdb_key = "ab-2",
            ipinfo_token = "ip-3",
        }
        helpers.redact_geoip_credentials(section)
        assert.equals("(redacted)", section.license_key)
        assert.equals("(redacted)", section.abuseipdb_key)
        assert.equals("(redacted)", section.ipinfo_token)
    end)

    it("leaves empty credentials empty (nothing to protect)", function()
        local section = { license_key = "", abuseipdb_key = "", ipinfo_token = "" }
        helpers.redact_geoip_credentials(section)
        assert.equals("", section.license_key)
        assert.equals("", section.abuseipdb_key)
        assert.equals("", section.ipinfo_token)
    end)

    it("tolerates a non-table section", function()
        helpers.redact_geoip_credentials(nil)
        helpers.redact_geoip_credentials("nope")
        assert.has_no_error(function()
            helpers.redact_geoip_credentials({ license_key = "x" })
        end)
    end)
end)

describe("config.save GeoIP credential sentinel backfill", function()
    local config

    setup(function()
        config = require "core.config"
    end)

    local function seed()
        config.save({
            version = "2.0",
            admin = { { user = "admin", password_hash = "p1$12000$REAL$HASH", enable = true } },
            matcher = {},
            rule = {},
            geoip = {
                license_key = "mm-live-1",
                abuseipdb_key = "ab-2",
                ipinfo_token = "ip-3",
            },
        })
    end

    it("backfills the real value for all three keys when the sentinel comes back", function()
        seed()
        local ok, err = config.save({
            version = "2.0",
            admin = { { user = "admin", password_hash = "p1$12000$REAL$HASH", enable = true } },
            matcher = {},
            rule = {},
            geoip = {
                license_key = "(redacted)",
                abuseipdb_key = "(redacted)",
                ipinfo_token = "(redacted)",
            },
        })
        assert.is_true(ok, "save with sentinels should succeed: " .. tostring(err))
        local g = config.geoip
        assert.equals("mm-live-1", g.license_key)
        assert.equals("ab-2", g.abuseipdb_key)
        assert.equals("ip-3", g.ipinfo_token,
            "the real ipinfo_token must survive the dashboard round trip")
    end)

    it("clears the sentinel to empty when the stored value is empty", function()
        seed()
        -- Overwrite with empty credentials first.
        config.save({
            version = "2.0",
            admin = { { user = "admin", password_hash = "p1$12000$REAL$HASH", enable = true } },
            matcher = {},
            rule = {},
            geoip = { license_key = "", abuseipdb_key = "", ipinfo_token = "" },
        })
        local ok = config.save({
            version = "2.0",
            admin = { { user = "admin", password_hash = "p1$12000$REAL$HASH", enable = true } },
            matcher = {},
            rule = {},
            geoip = {
                license_key = "(redacted)",
                abuseipdb_key = "(redacted)",
                ipinfo_token = "(redacted)",
            },
        })
        assert.is_true(ok)
        assert.equals("", config.geoip.license_key)
        assert.equals("", config.geoip.abuseipdb_key)
        assert.equals("", config.geoip.ipinfo_token,
            "an empty stored value must not resurrect the literal sentinel")
    end)

    it("accepts a new real value in place of the sentinel", function()
        seed()
        local ok = config.save({
            version = "2.0",
            admin = { { user = "admin", password_hash = "p1$12000$REAL$HASH", enable = true } },
            matcher = {},
            rule = {},
            geoip = {
                license_key = "mm-live-2",
                abuseipdb_key = "ab-9",
                ipinfo_token = "(redacted)",
            },
        })
        assert.is_true(ok)
        assert.equals("mm-live-2", config.geoip.license_key)
        assert.equals("ab-9", config.geoip.abuseipdb_key)
        assert.equals("ip-3", config.geoip.ipinfo_token,
            "the untouched credential keeps its stored value")
    end)
end)
