-- -*- coding: utf-8 -*-
-- Frequency limit plugin: counter namespace and CC evidence gate (Phase 0)
--
-- Self-contained: the plugin is loaded against stubbed config/matcher/evidence
-- so that what lands in the shared dict is exactly what the plugin decided.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 4
_G.ngx.time = function() return 1700000000 end
_G.ngx.now = function() return 1700000000 end
_G.ngx.md5 = function(s) return "x" end

local STORES = {}
local function mkdict()
    local st, cnt = {}, {}
    return {
        get = function(_, k) return st[k] end,
        set = function(_, k, v) st[k] = v; return true end,
        add = function(_, k, v) if st[k] then return false end; st[k] = v; return true end,
        incr = function(_, k, d, i) if st[k] == nil then st[k] = i or 0 end; st[k] = st[k] + d; return st[k] end,
        delete = function(_, k) st[k] = nil end,
        expire = function() end,
        flush_all = function() st, cnt = {}, {}; return true end,
        flush_expired = function() return 0 end,
        _keys = function() return st end,
    }
end
local DICTS = {}
_G.ngx.shared = setmetatable({}, {
    __index = function(_, name)
        if not DICTS[name] then DICTS[name] = mkdict() end
        return DICTS[name]
    end,
})

-- ------------------------------------------------------------------ mocks
local mock_config
local evidence_calls

local function reset(rules, kb)
    for _, d in pairs(DICTS) do d:flush_all() end
    mock_config = {
        local_hash = "h1",
        rule = { frequency_limit = rules or { { id = "r1", key = "ip", limit = 2, window = 60, enable = true } } },
        kernel_ip_blocking = kb or { enabled = false, mode = "observe",
                                     cc = { enabled = true, rule_ids = {} } },
    }
    package.loaded["core.config"] = mock_config
    package.loaded["matcher.init"] = {
        resolve = function(rule) return { dim = rule.key } end,
        test = function() return true end,
    }
    evidence_calls = {}
    package.loaded["core.kernel_blocking.evidence"] = {
        record_cc_violation_evidence = function(rule_id, ip, window)
            evidence_calls[#evidence_calls + 1] = { rule_id = rule_id, ip = ip, window = window }
        end,
        record_waf_block_evidence = function() end,
        record_challenge_fail_evidence = function() end,
        has_challenge_fail = function() return false end,
        sum_scanner_blocks = function() return 0 end,
        count_cc_violations = function() return 0 end,
    }
    package.loaded["plugin.frequency_limit.init"] = nil
end

local function make_ctx(ip)
    local data = {}
    return {
        request = { remote_addr = ip, uri = "/x", host = "h" },
        get_data = function(_, k) return data[k] end,
        set_data = function(_, k, v) data[k] = v end,
        set_action = function(self, act, opts) self.action = { act, opts } end,
    }
end

local function hit(plugin, ip, times)
    local ctx
    for _ = 1, times do
        ctx = make_ctx(ip)
        plugin.on_access(ctx)
    end
    return ctx
end

local function written_keys()
    local out = {}
    for k, v in pairs(DICTS.frequency_limit and DICTS.frequency_limit._keys() or {}) do
        out[#out + 1] = k
    end
    return out
end

describe("frequency_limit plugin", function()
    before_each(function() reset() end)

    it("counts in the single fl:count: namespace", function()
        local plugin = require "plugin.frequency_limit.init"
        hit(plugin, "1.2.3.4", 1)

        local keys = written_keys()
        assert.are.equal(1, #keys)
        assert.are.equal("fl:count:", keys[1]:sub(1, 9), "key: " .. keys[1])
        assert.falsy(keys[1]:find("v1", 1, true))
        assert.falsy(keys[1]:find("v2", 1, true))
    end)

    it("gives every rule its own counter", function()
        reset({ { id = "r1", key = "ip", limit = 10, window = 60, enable = true },
                { id = "r2", key = "ip", limit = 10, window = 60, enable = true } })
        local plugin = require "plugin.frequency_limit.init"
        hit(plugin, "1.2.3.4", 1)

        local keys = written_keys()
        assert.are.equal(2, #keys)
        assert.are_not.equal(keys[1], keys[2])
    end)

    it("counts a rule without an id under the rule-less key", function()
        reset({ { key = "ip", limit = 10, window = 60, enable = true } })
        local plugin = require "plugin.frequency_limit.init"
        hit(plugin, "1.2.3.4", 1)

        local keys = written_keys()
        assert.are.equal(1, #keys)
        assert.are.equal("fl:count:legacy:", keys[1]:sub(1, 16), "key: " .. keys[1])
    end)

    it("records evidence once, on the first transition past the limit", function()
        reset({ { id = "r1", key = "ip", limit = 2, window = 60, enable = true } },
              { enabled = true, mode = "observe", cc = { enabled = true, rule_ids = { "r1" } } })
        local plugin = require "plugin.frequency_limit.init"
        hit(plugin, "1.2.3.4", 5)

        assert.are.equal(1, #evidence_calls, "one evidence per rule per window")
        assert.are.equal("r1", evidence_calls[1].rule_id)
        assert.are.equal("1.2.3.4", evidence_calls[1].ip)
        assert.are.equal(60, evidence_calls[1].window)
    end)

    it("writes no evidence for a rule the CC policy does not reference", function()
        reset({ { id = "r1", key = "ip", limit = 2, window = 60, enable = true } },
              { enabled = true, mode = "observe", cc = { enabled = true, rule_ids = { "other" } } })
        local plugin = require "plugin.frequency_limit.init"
        hit(plugin, "1.2.3.4", 5)

        assert.are.equal(0, #evidence_calls,
            "evidence for a rule nobody reads is a dict write for nothing")
    end)

    it("writes no evidence while kernel blocking is off", function()
        reset({ { id = "r1", key = "ip", limit = 2, window = 60, enable = true } },
              { enabled = false, mode = "observe", cc = { enabled = true, rule_ids = { "r1" } } })
        local plugin = require "plugin.frequency_limit.init"
        hit(plugin, "1.2.3.4", 5)

        assert.are.equal(0, #evidence_calls)
    end)

    it("writes no evidence while the CC policy is off", function()
        reset({ { id = "r1", key = "ip", limit = 2, window = 60, enable = true } },
              { enabled = true, mode = "observe", cc = { enabled = false, rule_ids = { "r1" } } })
        local plugin = require "plugin.frequency_limit.init"
        hit(plugin, "1.2.3.4", 5)

        assert.are.equal(0, #evidence_calls)
    end)

    it("still limits when the counter cannot be written", function()
        -- Fail closed: a counter that could not be recorded must not turn the
        -- control off.
        local plugin = require "plugin.frequency_limit.init"
        local d = DICTS.frequency_limit
        d.incr = function() return nil, "no memory" end

        local ctx = make_ctx("1.2.3.4")
        plugin.on_access(ctx)
        assert.is_truthy(ctx.action)
        assert.are.equal("block", ctx.action[1])
    end)
end)
