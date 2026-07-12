-- -*- coding: utf-8 -*-
-- Tests for IP reputation public accessors and evidence collection (Phase 0)

local function setup_ngx()
    if not _G.ngx then _G.ngx = {} end
    local ngx = _G.ngx
    function ngx.log() end
    ngx.WARN = 6
    ngx.time = function() return 1700000000 end
    ngx.md5 = function(s) return "h_" .. tostring(s):sub(1, 8) end
    ngx.crc32_short = function() return 0 end
    ngx.shared = setmetatable({}, {
        __index = function(_, name)
            ngx._stores = ngx._stores or {}
            ngx._counters = ngx._counters or {}
            if not ngx._stores[name] then
                ngx._stores[name] = {}
                ngx._counters[name] = {}
            end
            local st = ngx._stores[name]
            local cnt = ngx._counters[name]
            return {
                get = function(_, key) return st[key] end,
                set = function(_, key, val) st[key] = val; return true end,
                add = function(_, key, val) if st[key] then return false end; st[key] = val; return true end,
                incr = function(_, key, delta, init) cnt[key] = (cnt[key] or (init or 0)) + delta; st[key] = cnt[key]; return cnt[key] end,
                delete = function(_, key) st[key] = nil; cnt[key] = nil end,
                expire = function(_, key, ttl) end,
                flush_all = function() for k in pairs(st) do st[k] = nil end; for k in pairs(cnt) do cnt[k] = nil end end,
            }
        end,
    })
    package.preload["bit"] = function()
        local m = {}
        function m.band(a, b) return 0 end
        return m
    end
end

setup_ngx()
local config = require "core.config"
local ir = require "core.ip_reputation"
local ev = require "core.kernel_blocking.evidence"

describe("IP reputation accessors", function()
    before_each(function()
        setup_ngx()
        config.save({
            version = "2.0", admin = {}, matcher = {}, rule = {},
            ip_reputation = {
                enable = false, threshold = 25, flag_duration = 600,
                window_size = 300, slot_size = 60, min_requests = 3,
                pending_ttl = 600, whitelist = {}, signals = {},
            },
        })
        package.loaded["core.ip_reputation"] = nil
        ir = require "core.ip_reputation"
    end)

    it("exposes slot_size()", function()
        setup_ngx()
        assert.are.equal(60, ir.slot_size())
    end)

    it("exposes window_size()", function()
        setup_ngx()
        assert.are.equal(300, ir.window_size())
    end)

    it("exposes flag_duration()", function()
        setup_ngx()
        assert.are.equal(600, ir.flag_duration())
    end)
end)

describe("Scanner evidence", function()
    before_each(function()
        setup_ngx()
        config.save({
            version = "2.0", admin = {}, matcher = {}, rule = {},
            ip_reputation = {
                enable = false, threshold = 25, flag_duration = 600,
                window_size = 300, slot_size = 60, min_requests = 3,
                pending_ttl = 600, whitelist = {}, signals = {},
            },
        })
        package.loaded["core.ip_reputation"] = nil
        package.loaded["core.kernel_blocking.evidence"] = nil
        ir = require "core.ip_reputation"
        ev = require "core.kernel_blocking.evidence"
        _G.ngx.shared.ip_reputation:flush_all()
    end)

    it("record_waf_block_evidence increments counter", function()
        setup_ngx()
        package.loaded["core.kernel_blocking.evidence"] = nil
        local ev2 = require "core.kernel_blocking.evidence"
        ev2.record_waf_block_evidence("203.0.113.5")
        ev2.record_waf_block_evidence("203.0.113.5")
        assert.are.equal(2, ev2.sum_scanner_blocks("203.0.113.5"))
    end)

    it("sum_scanner_blocks returns 0 for unknown IP", function()
        setup_ngx()
        assert.are.equal(0, ev.sum_scanner_blocks("1.2.3.4"))
    end)
end)
