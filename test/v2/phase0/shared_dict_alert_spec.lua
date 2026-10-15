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
    -- Mock a dict at a given water level holding a given number of keys.
    --
    -- The second condition is bytes-per-key, not key count. Measured on a real
    -- 32k zone on this host: 1 key → 12288 B/key, 40 → 409, 114 → 215, 191 →
    -- 171 at 100%. The count also SATURATES — it stopped at 191 while the dict
    -- was full and later writes only evicted earlier entries — so an absolute
    -- key floor would be unreachable on a small dict and would suppress the
    -- alert forever.
    --
    -- capacity()-free_space() reports the slab pool, sized by the worst traffic
    -- a dict has ever seen. This host read 99.9% of 16 MB while holding 114
    -- keys (~140 KB per key, which cannot exist), and a restart dropped it to
    -- 0.7% with no real entry changing. That is a large pool, and the
    -- per-key figure is what tells it apart from a crowded dict.
    -- used_pct and nkeys together determine bytes-per-key: a 1 MB zone fully
    -- used across 250 keys is 4000 B/key, across 244 keys is 4098 B/key.
    local function mock(dict, used_pct, nkeys)
        dict.capacity = function() return 1000000 end
        dict.free_space = function() return 1000000 * (100 - used_pct) / 100 end
        dict.get_keys = function()
            local t = {}
            for i = 1, nkeys do t[i] = "k" .. i end
            return t
        end
    end

    local function count_alerts()
        local n = 0
        package.loaded["core.metrics"].incr = function(name, _, labels)
            if name == "alert_fired_total" and labels
                and labels.type == "shared_dict_high_usage" then
                n = n + 1
            end
        end
        return function() return n end
    end

    before_each(function()
        ngx.shared.vn_config:flush_all()
        package.loaded["core.metrics"].incr = function() end
    end)

    it("does not fire when dict usage is below threshold", function()
        -- Default mock: free_space == capacity → 0% usage → no alert.
        local alerting = require "core.alerting"
        local fired = false
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

    -- 90% of 1 MB with 900 KB spread over 1000 keys → 900 B/key, under the
    -- 4096 limit: a genuinely crowded dict.
    it("fires when the level is high and the values are small", function()
        mock(ngx.shared.vn_config, 90, 1000)
        local get = count_alerts()
        require("core.alerting").evaluate()
        assert.are.equal(1, get())
    end)

    -- The regression this conjunction exists for: 99% used by 100 keys means
    -- 9000 B/key — a large pool holding a few large values, not a full dict.
    -- The old level-only check fired here.
    it("does not fire on a high level with few large values", function()
        mock(ngx.shared.vn_config, 99, 100)
        local get = count_alerts()
        require("core.alerting").evaluate()
        assert.are.equal(0, get(),
            "99% across 9000 B/key is a big pool, not a crowded dict")
    end)

    -- Guards the specific misreading this host already made: 114 keys reading
    -- 99.9% of 16 MB was ~140 KB per key, an impossible figure for a key-value
    -- entry and a large pool by any reading.
    it("does not fire on the historical 114-keys-at-99.9% reading", function()
        mock(ngx.shared.vn_config, 99, 114)
        local get = count_alerts()
        require("core.alerting").evaluate()
        assert.are.equal(0, get())
    end)

    it("fires at the bytes-per-key boundary", function()
        -- The limit is inclusive; otherwise the configured number would not
        -- mean what it says. Two key counts straddle it on a full 1 MB zone.
        mock(ngx.shared.vn_config, 100, 244)  -- 4098 B/key → above the limit
        local get = count_alerts()
        require("core.alerting").evaluate()
        assert.are.equal(0, get(), "4098 B/key is above the limit")

        ngx.shared.vn_config:flush_all()
        mock(ngx.shared.vn_config, 100, 250)  -- 4000 B/key → under the limit
        local get2 = count_alerts()
        require("core.alerting").evaluate()
        assert.are.equal(1, get2(), "4000 B/key must alert")
    end)

    -- fire_alert is a local function, so the detail payload is only observable
    -- through the webhook. Point one at a stub resty.http and read what the
    -- alert would have carried — otherwise "the key count is in the payload"
    -- is a claim nothing checks.
    it("carries the key count and the per-key figure in the payload", function()
        mock(ngx.shared.vn_config, 90, 1000)

        local sent = {}
        package.loaded["resty.http"] = {
            new = function()
                return {
                    set_timeout = function() end,
                    request_uri = function(_, _, opts)
                        sent[#sent + 1] = opts.body
                        return { status = 200 }
                    end,
                }
            end,
        }
        -- A public literal IP, so validate_webhook_url accepts it without a DNS
        -- round trip. 127.0.0.1 is refused as loopback, which is the SSRF
        -- guard working and would leave the payload unobserved here.
        package.loaded["core.config"].alerting.webhook_url = "https://203.0.113.7/hook"

        require("core.alerting").evaluate()
        package.loaded["core.config"].alerting.webhook_url = ""
        package.loaded["resty.http"] = nil

        local body = sent[1]
        assert.is_truthy(body, "the alert must reach the webhook when one is configured")
        local d = require("dkjson").decode(body).detail
        assert.are.equal(1000, d.keys)
        assert.is_true(d.keys_counted, "and say it was counted, not guessed")
        assert.are.equal(900, d.bytes_per_key, "900000 bytes over 1000 keys")
        assert.are.equal(4096, d.max_bytes_per_key_allowed)
        assert.are.equal(90, d.usage_pct)
        -- LRU eviction here reports success, so this is the state where
        -- counters start vanishing without an error. The payload should not
        -- leave that to be recalled.
        assert.is_true(d.eviction_possible)
    end)

    it("alerts when the level is high and the key count cannot be read", function()
        -- get_keys erroring is one fewer diagnostic available, not a reason to
        -- fall back to the level alone — the level alone is the reading that
        -- has misled this deployment before.
        mock(ngx.shared.vn_config, 95, 0)
        ngx.shared.vn_config.get_keys = function() error("boom") end
        local get = count_alerts()
        require("core.alerting").evaluate()
        assert.are.equal(1, get(), "an uncountable dict at 95% must still alert")
    end)

    -- Cooldown regression (audit M-20): fire_alert sets cd_key
    -- "<type>:<rule_id>" with ttl = window_seconds * 2; a second evaluation
    -- inside the window must be suppressed, while a DIFFERENT dict gets its
    -- own cooldown key and still fires.
    it("suppresses repeat alerts inside the cooldown window", function()
        mock(ngx.shared.vn_config, 90, 1000)
        local get = count_alerts()

        local alerting = require "core.alerting"
        alerting.evaluate()
        alerting.evaluate()  -- immediately again — must be cooled down
        assert.are.equal(1, get())
    end)

    it("keeps per-dict cooldowns independent", function()
        local get = count_alerts()
        local alerting = require "core.alerting"

        for _, name in ipairs({ "vn_config", "metrics" }) do
            mock(ngx.shared[name], 90, 1000)
        end

        alerting.evaluate()
        assert.are.equal(2, get())  -- one per distinct dict
    end)
end)
