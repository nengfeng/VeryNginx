-- -*- coding: utf-8 -*-
-- Tests for GET /kernel-blocking/bucket-history and GET /kernel-blocking/diff.
-- Covers endpoints explicitly untested per AGENTS.md 12.3.

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7; _G.ngx.NOTICE = 8
_G.ngx.time = function() return 1700000000 end
_G.ngx.sleep = function() end
_G.ngx.shared = setmetatable({_cache = {}}, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v) st[k] = v; return true, nil end,
                add = function(_, k, v)
                    if st[k] then return false, "exists" end
                    st[k] = v; return true, nil
                end,
                incr = function(_, k, d, i)
                    if st[k] == nil then st[k] = (i or 0) end
                    st[k] = st[k] + d; return st[k], nil
                end,
                delete = function(_, k) st[k] = nil end,
                expire = function() end,
                flush_all = function()
                    for k in pairs(st) do st[k] = nil end
                end,
            }
        end
        return t._cache[name]
    end,
})

local mock_config = {
    kernel_ip_blocking = {
        enabled = true, mode = "enforce", topology = "direct",
        fail_policy = "open", emergency_pause = false,
        ipv4 = { enabled = true }, ipv6 = { enabled = false },
        scanner = { enabled = true, min_hard_blocks = 3, max_ttl = 86400 },
        cc = {
            enabled = true, enforce_ready = false,
            rule_ids = {"freq_rule_1"}, ttl = 300, max_ttl = 1800,
        },
    },
}
package.loaded["core.config"] = setmetatable(mock_config, {
    __index = function(t, k) return rawget(t, k) end,
})

package.loaded["core.audit"] = { log = function() end }
package.loaded["core.metrics"] = {
    incr = function() end, gauge = function() end,
}

local desired = require "core.kernel_blocking.desired_state"
local mock = require "core.kernel_blocking.executor_mock"
package.loaded["core.kernel_blocking.executor"] = {
    get_executor = function() return mock end,
    get_mock = function() return mock end,
}
local kb = require "core.kernel_blocking.init"

describe("GET /kernel-blocking/bucket-history", function()
    before_each(function()
        ngx.shared.vn_locks:flush_all()
        ngx.shared.vn_config:flush_all()
        mock_config.kernel_ip_blocking.enabled = true
    end)

    it("returns empty table when no history sampled", function()
        local h = kb.get_bucket_history()
        assert.are.equal("table", type(h))
        local n = 0
        for _ in pairs(h) do n = n + 1 end
        assert.are.equal(0, n)
    end)

    it("sample and retrieve one history point", function()
        kb.sample_bucket_history()
        local h = kb.get_bucket_history()
        local n = 0
        for _ in pairs(h) do n = n + 1 end
        assert.are.equal(1, n)
        for _, v in pairs(h) do
            assert.are.equal("table", type(v))
            assert.truthy(v.t)
            assert.truthy(v.enforce_tokens ~= nil)
            assert.truthy(v.observe_tokens ~= nil)
        end
    end)

    it("throttles: second sample within 300s is skipped", function()
        kb.sample_bucket_history()
        kb.sample_bucket_history()
        local h = kb.get_bucket_history()
        local n = 0
        for _ in pairs(h) do n = n + 1 end
        assert.are.equal(1, n)
    end)

    it("circular buffer wraps at max capacity", function()
        for _ = 1, 50 do
            ngx.shared.vn_locks:delete("kb:bucket_history:last")
            kb.sample_bucket_history()
        end
        local h = kb.get_bucket_history()
        local n = 0
        for _ in pairs(h) do n = n + 1 end
        assert.are.equal(50, n)
    end)
end)

describe("GET /kernel-blocking/diff", function()
    before_each(function()
        ngx.shared.vn_locks:flush_all()
        ngx.shared.vn_config:flush_all()
        mock.flush_owned("all")
        mock_config.kernel_ip_blocking.enabled = true
    end)

    it("empty diff when no desired and no actual", function()
        local diff = kb.get_diff()
        assert.are.equal("table", type(diff))
        assert.are.equal(0, #diff.missing_in_kernel)
        assert.are.equal(0, #diff.orphan_in_kernel)
        assert.are.equal(0, diff.desired_count)
        assert.are.equal(0, diff.actual_count)
    end)

    it("reports missing_in_kernel for desired but not installed", function()
        mock.ensure_base(mock_config.kernel_ip_blocking)
        desired.set_desired("203.0.113.10", "ipv4", "scanner_drop",
            {}, 600, { source = "automatic", policy = "scanner" })
        local diff = kb.get_diff()
        assert.are.equal(1, #diff.missing_in_kernel)
        assert.are.equal("203.0.113.10", diff.missing_in_kernel[1].ip)
        assert.are.equal("scanner_drop", diff.missing_in_kernel[1].list)
        assert.are.equal(0, #diff.orphan_in_kernel)
        assert.are.equal(1, diff.desired_count)
        assert.are.equal(0, diff.actual_count)
    end)

    it("reports orphan_in_kernel for installed but not desired", function()
        mock.ensure_base(mock_config.kernel_ip_blocking)
        mock.add("manual_drop", "ipv4", "198.51.100.50", 300)
        local diff = kb.get_diff()
        assert.are.equal(0, #diff.missing_in_kernel)
        assert.are.equal(1, #diff.orphan_in_kernel)
        assert.are.equal("198.51.100.50", diff.orphan_in_kernel[1].ip)
        assert.are.equal("manual_drop", diff.orphan_in_kernel[1].list)
        assert.are.equal(0, diff.desired_count)
        assert.are.equal(1, diff.actual_count)
    end)

    it("reports both missing and orphan simultaneously", function()
        mock.ensure_base(mock_config.kernel_ip_blocking)
        desired.set_desired("203.0.113.10", "ipv4", "scanner_drop",
            {}, 600, { source = "automatic", policy = "scanner" })
        mock.add("manual_drop", "ipv4", "198.51.100.50", 300)
        local diff = kb.get_diff()
        assert.are.equal(1, #diff.missing_in_kernel)
        assert.are.equal(1, #diff.orphan_in_kernel)
        assert.are.equal(1, diff.desired_count)
        assert.are.equal(1, diff.actual_count)
    end)

    it("matches desired and actual when both present (no drift)", function()
        mock.ensure_base(mock_config.kernel_ip_blocking)
        desired.set_desired("203.0.113.10", "ipv4", "scanner_drop",
            {}, 600, { source = "automatic", policy = "scanner" })
        mock.add("scanner_drop", "ipv4", "203.0.113.10", 600)
        local diff = kb.get_diff()
        assert.are.equal(0, #diff.missing_in_kernel)
        assert.are.equal(0, #diff.orphan_in_kernel)
        assert.are.equal(1, diff.desired_count)
        assert.are.equal(1, diff.actual_count)
    end)
end)
