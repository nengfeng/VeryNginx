-- -*- coding: utf-8 -*-
-- @Disc    : persist/restore of per-rule stats — the per-day counter
--            (waf_rule_stats:<id>:today:<utcday>) lives only in the
--            restart-reset vn_config dict while the lifetime blob is
--            persisted; these specs pin the carry-over so "今日命中"
--            does not silently drop to 0 on a full restart.

describe("waf-rule-manager persist/restore rule stats", function()
    local waf
    local json
    local stats_path
    local saved_content

    setup(function()
        waf = require("waf-rule-manager")
        json = require("dkjson")
        local config = require("core.config")
        stats_path = config.resolve_path() .. "configs/waf-rule-stats.json"
        local f = io.open(stats_path, "r")
        saved_content = f and f:read("*all") or nil
        if f then f:close() end
    end)

    after_each(function()
        -- Restore the original stats file (or remove ours), reset the
        -- "restored" guard and the shared dict so sibling specs are not
        -- affected.
        if saved_content then
            local f = io.open(stats_path, "w")
            if f then f:write(saved_content); f:close() end
        else
            os.remove(stats_path)
        end
        ngx.shared.vn_config:delete("waf_rule_stats:restored")
        ngx.shared.vn_config:flush_all()
    end)

    it("persist_rule_stats carries today's daily counter into the file", function()
        local shared = ngx.shared.vn_config
        shared:flush_all()
        local day = os.date("!%Y%m%d")
        shared:set("waf_rule_stats:r1",
            json.encode({ hit_count = 100, block_count = 80, challenge_count = 5, last_triggered = 123 }))
        shared:set("waf_rule_stats:index", "r1\n")
        shared:set("waf_rule_stats:r1:today:" .. day, 7)
        waf.persist_rule_stats()
        local f = io.open(stats_path, "r")
        assert.truthy(f)
        local file_stats = json.decode(f:read("*all"))
        f:close()
        assert.are.equal(7, file_stats.r1.today_hits)
        assert.are.equal(day, file_stats.r1.today_utc_day)
        assert.are.equal(100, file_stats.r1.hit_count)
    end)

    it("restore_rule_stats restores today's daily counter for the current day", function()
        local shared = ngx.shared.vn_config
        shared:flush_all()
        local day = os.date("!%Y%m%d")
        local f = io.open(stats_path, "w")
        assert.truthy(f)
        f:write(json.encode({ r1 = { hit_count = 100, block_count = 80, today_utc_day = day, today_hits = 7 } }))
        f:close()
        waf.restore_rule_stats()
        assert.are.equal(7, tonumber(shared:get("waf_rule_stats:r1:today:" .. day)))
        assert.are.equal(100, json.decode(shared:get("waf_rule_stats:r1")).hit_count)
    end)

    it("restore_rule_stats ignores a stale day's counter", function()
        local shared = ngx.shared.vn_config
        shared:flush_all()
        local f = io.open(stats_path, "w")
        assert.truthy(f)
        f:write(json.encode({ r1 = { hit_count = 100, today_utc_day = "20200101", today_hits = 7 } }))
        f:close()
        waf.restore_rule_stats()
        assert.is_nil(shared:get("waf_rule_stats:r1:today:20200101"))
    end)
end)
