-- -*- coding: utf-8 -*-
-- Tests for shared_dict_high_usage alert in core/alerting.lua.

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7; _G.ngx.NOTICE = 8
_G.ngx.time = function() return 1700000000 end
_G.ngx.shared = setmetatable({_cache = {}}, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v) st[k] = v; return true, nil end,
                add = function(_, k, v) if st[k] then return false, "exists" end; st[k] = v; return true, nil end,
                incr = function(_, k, d, i) if st[k] == nil then st[k] = (i or 0) end; st[k] = st[k] + d; return st[k], nil end,
                delete = function(_, k) st[k] = nil end,
                capacity = function() return 1024 * 1024 end,
                free_space = function() return 1024 * 1024 end,
                get_keys = function(_) return {} end,
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
            }
        end
        return t._cache[name]
    end,
})

package.loaded["core.config"] = {
    alerting = {
        enabled = true,
        webhook_url = "",
        shared_dict_alert_threshold = 80,
        window_seconds = 360,
    },
}
package.loaded["core.metrics"] = {
    incr = function() end,
    gauge = function() end,
}
package.loaded["core.audit"] = { log = function() end }
package.loaded["waf-rule-manager"] = { load_rules = function() return { rules = {} } end }

describe("shared_dict_high_usage alert", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
    end)

    it("does not fire when dict usage is below threshold", function()
        -- Default mock: free_space == capacity → 0% usage → no alert.
        local alerting = require "core.alerting"
        local fired = false
        local orig_fire = alerting._test_fire_alert
        -- Override fire_alert indirectly by tracking metrics.incr calls.
        local incr_calls = {}
        package.loaded["core.metrics"].incr = function(name, _, labels)
            incr_calls[#incr_calls + 1] = { name = name, type = labels and labels.type }
        end
        alerting.evaluate()
        for _, c in ipairs(incr_calls) do
            if c.type == "shared_dict_high_usage" then
                fired = true
            end
        end
        assert.is_false(fired)
    end)

    it("fires when dict usage exceeds threshold", function()
        -- Make vn_config report 90% usage (free_space = 10% of capacity).
        local dict = ngx.shared.vn_config
        dict.capacity = function() return 1000000 end
        dict.free_space = function() return 100000 end  -- 90% used

        local incr_calls = {}
        package.loaded["core.metrics"].incr = function(name, _, labels)
            incr_calls[#incr_calls + 1] = { name = name, type = labels and labels.type }
        end

        local alerting = require "core.alerting"
        alerting.evaluate()

        local found = false
        for _, c in ipairs(incr_calls) do
            if c.type == "shared_dict_high_usage" then found = true end
        end
        assert.is_true(found)
    end)
end)
