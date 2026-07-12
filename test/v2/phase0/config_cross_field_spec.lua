-- -*- coding: utf-8 -*-
-- Tests for kernel_ip_blocking cross-field validation (Design §11.3)

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

local function ensure_ngx()
    if not _G.ngx then _G.ngx = {} end
    local ngx = _G.ngx
    function ngx.log() end
    ngx.WARN = 6; ngx.ERR = 5
    ngx.time = function() return 1700000000 end
    ngx.md5 = function(s) return "x" end
    ngx.shared = setmetatable({}, {
        __index = function(_, name)
            ngx._stores = ngx._stores or {}
            if not ngx._stores[name] then ngx._stores[name] = {} end
            local st = ngx._stores[name]
            return {
                get = function(_, key) return st[key] end,
                set = function(_, key, val) st[key] = val; return true end,
                add = function(_, key, val)
                    if st[key] then return false end
                    st[key] = val; return true end,
                delete = function(_, key) st[key] = nil end,
                expire = function(_, key, ttl) end,
            }
        end,
    })
end
ensure_ngx()

local config = require "core.config"

local function base_kb()
    return {
        enabled = false, mode = "observe", topology = "unknown",
        fail_policy = "open", scope = "web",
        batch_interval = 1, reconcile_interval = 30,
        scanner = { enabled = true, max_ttl = 86400 },
        cc = { enabled = true, ttl = 300, max_ttl = 1800 },
        ipv4 = { enabled = true },
        ipv6 = { enabled = false, prefix_aggregation = false },
    }
end

describe("kernel_ip_blocking cross-field validation", function()
    before_each(function()
        ensure_ngx()
        config.save({ version = "2.0", admin = {}, matcher = {}, rule = {} })
    end)

    it("rejects reconcile_interval < batch_interval", function()
        ensure_ngx()
        local kb = base_kb()
        kb.batch_interval = 30
        kb.reconcile_interval = 10
        local ok, err = config.validate_config({
            version = "2.0", admin = {}, matcher = {}, rule = {},
            kernel_ip_blocking = kb,
        })
        assert.is_false(ok)
        assert.truthy(err:find("reconcile_interval"))
    end)

    it("rejects cc.max_ttl < cc.ttl", function()
        ensure_ngx()
        local kb = base_kb()
        kb.cc.max_ttl = 200
        kb.cc.ttl = 300
        local ok, err = config.validate_config({
            version = "2.0", admin = {}, matcher = {}, rule = {},
            kernel_ip_blocking = kb,
        })
        assert.is_false(ok)
        assert.truthy(err:find("max_ttl"))
    end)

    it("rejects scanner.max_ttl < ip_reputation.flag_duration", function()
        ensure_ngx()
        local kb = base_kb()
        kb.scanner.max_ttl = 300  -- less than default flag_duration=600
        local ok, err = config.validate_config({
            version = "2.0", admin = {}, matcher = {}, rule = {},
            ip_reputation = { flag_duration = 600 },
            kernel_ip_blocking = kb,
        })
        assert.is_false(ok)
        assert.truthy(err:find("max_ttl"))
        assert.truthy(err:find("flag_duration"))
    end)

    it("rejects enforce without topology=direct", function()
        ensure_ngx()
        local kb = base_kb()
        kb.enabled = true
        kb.mode = "enforce"
        kb.topology = "unknown"
        kb.protected_addresses = { "10.0.0.1" }
        kb.protected_ports = { 80, 443 }
        local ok, err = config.validate_config({
            version = "2.0", admin = {}, matcher = {}, rule = {},
            kernel_ip_blocking = kb,
        })
        assert.is_false(ok)
        assert.truthy(err:find("topology"))
    end)

    it("rejects enforce without protected_addresses", function()
        ensure_ngx()
        local kb = base_kb()
        kb.enabled = true
        kb.mode = "enforce"
        kb.topology = "direct"
        kb.protected_addresses = {}
        kb.protected_ports = { 80, 443 }
        local ok, err = config.validate_config({
            version = "2.0", admin = {}, matcher = {}, rule = {},
            kernel_ip_blocking = kb,
        })
        assert.is_false(ok)
        assert.truthy(err:find("protected_addresses"))
    end)

    it("rejects enforce without protected_ports", function()
        ensure_ngx()
        local kb = base_kb()
        kb.enabled = true
        kb.mode = "enforce"
        kb.topology = "direct"
        kb.protected_addresses = { "10.0.0.1" }
        kb.protected_ports = {}
        local ok, err = config.validate_config({
            version = "2.0", admin = {}, matcher = {}, rule = {},
            kernel_ip_blocking = kb,
        })
        assert.is_false(ok)
        assert.truthy(err:find("protected_ports"))
    end)

    it("rejects enforce with ipv6.prefix_aggregation=true", function()
        ensure_ngx()
        local kb = base_kb()
        kb.enabled = true
        kb.mode = "enforce"
        kb.topology = "direct"
        kb.protected_addresses = { "10.0.0.1" }
        kb.protected_ports = { 80 }
        kb.ipv6.enabled = true
        kb.ipv6.prefix_aggregation = true
        local ok, err = config.validate_config({
            version = "2.0", admin = {}, matcher = {}, rule = {},
            kernel_ip_blocking = kb,
        })
        assert.is_false(ok)
        assert.truthy(err:find("prefix_aggregation"))
    end)

    it("rejects enforce with no address family enabled", function()
        ensure_ngx()
        local kb = base_kb()
        kb.enabled = true
        kb.mode = "enforce"
        kb.topology = "direct"
        kb.protected_addresses = { "10.0.0.1" }
        kb.protected_ports = { 80 }
        kb.ipv4.enabled = false
        local ok, err = config.validate_config({
            version = "2.0", admin = {}, matcher = {}, rule = {},
            kernel_ip_blocking = kb,
        })
        assert.is_false(ok)
        assert.truthy(err:find("address family"))
    end)

    it("accepts valid observe mode (all defaults)", function()
        ensure_ngx()
        local ok, err = config.validate_config({
            version = "2.0", admin = {}, matcher = {}, rule = {},
            kernel_ip_blocking = base_kb(),
        })
        assert.is_true(ok, "should accept observe mode: " .. tostring(err))
    end)

    it("accepts valid enforce mode with all gates satisfied", function()
        ensure_ngx()
        local kb = base_kb()
        kb.enabled = true
        kb.mode = "enforce"
        kb.topology = "direct"
        kb.protected_addresses = { "10.0.0.1", "192.168.1.0/24" }
        kb.protected_ports = { 80, 443 }
        local ok, err = config.validate_config({
            version = "2.0", admin = {}, matcher = {}, rule = {},
            kernel_ip_blocking = kb,
        })
        assert.is_true(ok, "should accept valid enforce: " .. tostring(err))
    end)
end)
