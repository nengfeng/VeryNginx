-- -*- coding: utf-8 -*-
-- Tests for GeoIP directory/file permission hardening (no 777).

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end

describe("GeoIP permission hardening", function()
    it("geoip.lua does not use chmod 777 or mkdir -m 777", function()
        local f = io.open("verynginx/core/geoip.lua", "r")
        assert.truthy(f, "geoip.lua not found")
        local content = f:read("*a")
        f:close()
        assert.is_nil(content:match("777"), "geoip.lua still contains 777")
    end)

    it("geoip_updater.lua does not use chmod 777", function()
        local f = io.open("verynginx/core/geoip_updater.lua", "r")
        assert.truthy(f, "geoip_updater.lua not found")
        local content = f:read("*a")
        f:close()
        assert.is_nil(content:match("777"), "geoip_updater.lua still contains 777")
    end)

    it("geoip_updater.lua ensures 755 on directories", function()
        local f = io.open("verynginx/core/geoip_updater.lua", "r")
        assert.truthy(f)
        local content = f:read("*a")
        f:close()
        assert.truthy(content:match("755"), "geoip_updater.lua should set 755 on directories")
    end)

    it("geoip_updater.lua ensures 644 on downloaded files", function()
        local f = io.open("verynginx/core/geoip_updater.lua", "r")
        assert.truthy(f)
        local content = f:read("*a")
        f:close()
        assert.truthy(content:match("644"), "geoip_updater.lua should set 644 on files")
    end)
end)
