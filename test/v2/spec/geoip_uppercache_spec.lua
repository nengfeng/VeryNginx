-- -*- coding: utf-8 -*-
-- Regression guard for the GeoIP block-list uppercase cache.
--
-- check_block() used to call c:upper() on every whitelist/blocklist/continent
-- entry on EVERY request. lists are cached by source-table identity, so a
-- config reload (which replaces config_data wholesale) invalidates them.

describe("geoip check_block uppercases config lists once", function()
    local geoip
    local saved_config

    local function load_with(cfg)
        saved_config = package.loaded["core.config"]
        package.loaded["core.config"] = { geoip = cfg }
        package.loaded["core.geoip"] = nil
        geoip = require("core.geoip")
    end

    teardown(function()
        package.loaded["core.config"] = saved_config
        package.loaded["core.geoip"] = nil
    end)

    it("matches lowercase lists against an uppercase country code", function()
        load_with({ enable = true, whitelist = { "cn", "us" } })
        local blocked, reason = geoip.check_block("1.2.3.4", {
            country_code = "US", continent = "NA",
        })
        assert.is_false(blocked)
        assert.is_nil(reason)
    end)

    it("matches a mixed-case blocklist entry", function()
        load_with({ enable = true, blocklist = { "rU" } })
        local blocked, reason = geoip.check_block("1.2.3.4", {
            country_code = "RU", continent = "EU",
        })
        assert.is_true(blocked)
        assert.is_equal("geoip:blocklist:RU", reason)
    end)

    it("matches continent list case-insensitively", function()
        load_with({ enable = true, block_continents = { "na" } })
        local blocked, reason = geoip.check_block("1.2.3.4", {
            country_code = "US", continent = "NA",
        })
        assert.is_true(blocked)
        assert.is_equal("geoip:block_continent:NA", reason)
    end)

    it("invalidates the uppercase cache when config lists are replaced", function()
        local cfg = { enable = true, blocklist = { "ru" } }
        load_with(cfg)
        assert.is_true(geoip.check_block("1.2.3.4", { country_code = "RU" }))

        -- Simulate a config reload: a NEW list object replaces the old one.
        cfg.blocklist = { "us" }
        assert.is_false(geoip.check_block("1.2.3.4", { country_code = "RU" }))
        assert.is_true(geoip.check_block("1.2.3.4", { country_code = "US" }))
    end)
end)
