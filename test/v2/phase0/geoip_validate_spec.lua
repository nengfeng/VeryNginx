-- -*- coding: utf-8 -*-
-- Unit tests for core.geoip.validate_mmdb — the download gate that rejected
-- EVERY file ("no \xAB\xCD\xEF marker in the final 128KiB") because its
-- last-occurrence loop used the loop condition itself (`until idx == nil`)
-- as the result. These tests pin the real behaviour: real MaxMind layout
-- accepted (including files far larger than the scan window), error pages
-- rejected, markers outside the tail window rejected, tiny files rejected.

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
if not _G.ngx.log then _G.ngx.log = function() end end
_G.ngx.ERR = _G.ngx.ERR or 5

describe("core.geoip.validate_mmdb", function()
    local geoip
    local DIR = "/tmp/vnt-spec"

    local function write_file(name, content)
        os.execute("mkdir -p " .. DIR)
        local path = DIR .. "/" .. name
        local f = assert(io.open(path, "wb"))
        f:write(content)
        f:close()
        return path
    end

    setup(function()
        -- Other phase0 specs inject a fake core.geoip into package.loaded;
        -- load the REAL module for these tests and leave no trace behind.
        package.loaded["core.geoip"] = nil
        geoip = require "core.geoip"
        assert.truthy(geoip.validate_mmdb, "validate_mmdb must be exported")
    end)

    teardown(function()
        package.loaded["core.geoip"] = nil
        for _, n in ipairs({ "good.mmdb", "big.mmdb", "html.mmdb",
                             "early-marker.mmdb", "tiny.mmdb" }) do
            os.remove(DIR .. "/" .. n)
        end
    end)

    it("accepts a MaxMind-layout file (marker near EOF)", function()
        local p = write_file("good.mmdb",
            string.rep("\0", 2048) .. "\xAB\xCD\xEFMaxMind.com" .. string.rep("\0", 200))
        assert.is_true(geoip.validate_mmdb(p))
    end)

    it("accepts a file far larger than the scan window (marker close to EOF)", function()
        local p = write_file("big.mmdb",
            string.rep("A", 300 * 1024) .. "\xAB\xCD\xEFMaxMind.com" .. string.rep("B", 100))
        assert.is_true(geoip.validate_mmdb(p))
    end)

    it("rejects an HTML/JSON error page saved under a .mmdb name", function()
        local p = write_file("html.mmdb",
            "<html><body>404 Not Found</body></html>" .. string.rep("!", 2048))
        local ok, err = geoip.validate_mmdb(p)
        assert.is_false(ok)
        assert.truthy(tostring(err):find("not a MaxMind DB", 1, true),
            "error must explain the missing marker: " .. tostring(err))
    end)

    it("rejects a file whose only marker sits BEYOND the final 128KiB", function()
        local p = write_file("early-marker.mmdb",
            "\xAB\xCD\xEFMaxMind.com" .. string.rep("C", 300 * 1024))
        assert.is_false(geoip.validate_mmdb(p))
    end)

    it("rejects files below the minimum size", function()
        local p = write_file("tiny.mmdb", "\xAB\xCD\xEF")
        local ok, err = geoip.validate_mmdb(p)
        assert.is_false(ok)
        assert.truthy(tostring(err):find("too small", 1, true))
    end)
end)
