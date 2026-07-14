package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

local statistics = require "core.statistics"
local config = require "core.config"

describe("Statistics worker initialization", function()
    local original_worker
    local original_timer
    local original_restore
    local original_json_path
    local original_statistics_config
    local temp_path

    before_each(function()
        original_worker = ngx.worker
        original_timer = ngx.timer
        original_restore = statistics.restore
        original_json_path = statistics._json_path
        original_statistics_config = config.statistics
        temp_path = nil
        ngx.shared.statistics:flush_all()
    end)

    after_each(function()
        ngx.worker = original_worker
        ngx.timer = original_timer
        statistics.restore = original_restore
        statistics._json_path = original_json_path
        config.statistics = original_statistics_config
        if temp_path then os.remove(temp_path) end
    end)

    it("registers maintenance only on worker zero", function()
        local every_calls = 0
        local at_calls = 0
        local restore_calls = 0
        ngx.worker = {
            id = function() return 1 end,
            exiting = function() return false end,
        }
        ngx.timer = {
            every = function() every_calls = every_calls + 1 end,
            at = function() at_calls = at_calls + 1 end,
        }
        statistics.restore = function() restore_calls = restore_calls + 1 end

        statistics.init()

        assert.are.equal(0, every_calls)
        assert.are.equal(0, at_calls)
        assert.are.equal(0, restore_calls)
    end)

    it("registers one set of maintenance timers on worker zero", function()
        local every_calls = 0
        local at_calls = 0
        local restore_calls = 0
        ngx.worker = {
            id = function() return 0 end,
            exiting = function() return false end,
        }
        ngx.timer = {
            every = function() every_calls = every_calls + 1 end,
            at = function() at_calls = at_calls + 1 end,
        }
        statistics.restore = function() restore_calls = restore_calls + 1 end

        statistics.init()

        assert.are.equal(4, every_calls)
        assert.are.equal(1, at_calls)
        assert.are.equal(1, restore_calls)
    end)

    it("merges persisted data without replacing live statistics", function()
        config.statistics = { max_uri_keys = 3 }
        ngx.shared.statistics:set("index:all", '["/live"]')
        ngx.shared.statistics:set("all:/live:count", 5)
        temp_path = os.tmpname()
        local f = assert(io.open(temp_path, "w"))
        f:write('{"/persisted":{"count":2,"bytes":20,"time":0.5}}')
        f:close()
        statistics._json_path = function() return temp_path end

        statistics.restore()

        local index = require("dkjson").decode(ngx.shared.statistics:get("index:all"))
        assert.are.equal(2, #index)
        assert.are.equal("/live", index[1])
        assert.are.equal(5, ngx.shared.statistics:get("all:/live:count"))
        assert.are.equal(2, ngx.shared.statistics:get("all:/persisted:count"))
    end)
end)
