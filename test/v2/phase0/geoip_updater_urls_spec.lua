-- -*- coding: utf-8 -*-
-- Unit tests for geoip_updater._build_url_list: the candidate URL ordering
-- that used to let one dead configured URL (the legacy jsdelivr default,
-- which 404s because the npm package ships only the .gz) exclude the
-- built-in mirrors and fail every update forever.

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5
_G.ngx.time = function() return 1700000000 end

local MIRRORS = {
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb",
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb",
    "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb",
}
local DEAD = "https://cdn.jsdelivr.net/npm/geolite2-city@latest/GeoLite2-City.mmdb"

describe("geoip_updater._build_url_list", function()
    local build

    setup(function()
        -- Minimal stubs so the module loads without a runtime
        package.loaded["core.audit"] = { log = function() end }
        package.loaded["core.dict_guard"] = {
            set = function() return true end,
            incr = function() return true end,
            write_failed = function() end,
        }
        package.loaded["core.geoip"] = {
            reload = function() return true end,
            get_status = function() return {} end,
        }
        package.loaded["core.config"] = { geoip = {} }
        local m = require "core.geoip_updater"
        build = m._build_url_list
        assert.truthy(build, "_build_url_list must be exported")
    end)

    it("appends the built-in mirrors even when a configured URL is present", function()
        local urls = build({
            cdn_url = "https://example.com/db.mmdb",
            update_url = "",
            use_cdn = false,
        }, nil)
        assert.are.equal("https://example.com/db.mmdb", urls[1])
        for i, m in ipairs(MIRRORS) do
            assert.are.equal(m, urls[#urls - #MIRRORS + i])
        end
    end)

    it("filters the known-dead legacy jsdelivr default (configs carrying it heal)", function()
        local urls = build({
            cdn_url = DEAD,
            update_url = "",
            use_cdn = false,
        }, nil)
        for _, u in ipairs(urls) do
            assert.not_equals(DEAD, u)
        end
        -- And the mirrors still follow.
        assert.are.equal(MIRRORS[1], urls[1])
    end)

    it("puts the licensed MaxMind endpoint first and dedupes", function()
        local urls = build({
            cdn_url = "",
            update_url = "",
            use_cdn = false,
        }, "abc123")
        assert.truthy(urls[1]:find("download%.maxmind%.com", 1))
        assert.truthy(urls[1]:find("license_key=abc123", 1, true))
        assert.are.equal(#MIRRORS + 1, #urls)
        -- No duplicates even if a user URL equals a mirror.
        local urls2 = build({
            cdn_url = MIRRORS[1],
            update_url = MIRRORS[1],
            use_cdn = false,
        }, nil)
        assert.are.equal(#MIRRORS, #urls2)
    end)

    it("returns just the mirrors when nothing is configured (fresh install)", function()
        local urls = build({ cdn_url = "", update_url = "", use_cdn = false }, "")
        assert.are.equal(#MIRRORS, #urls)
        assert.are.equal(MIRRORS[1], urls[1])
    end)
end)
