-- -*- coding: utf-8 -*-
-- api/helpers.is_valid_ip — IPv4-mapped IPv6 literal acceptance.
-- Audit leftover: "::ffff:8.8.8.8" was rejected as invalid, so operators
-- pasting mapped-form addresses into reputation/whitelist/frequency IP
-- fields got 400s. The embedded IPv4 must be validated (and CIDR still
-- rejected — the matcher engine has no prefix semantics).
package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

describe("is_valid_ip mapped-form (::ffff:) 支持", function()
    local helpers

    setup(function()
        package.loaded["api.helpers"] = nil
        helpers = require("api.helpers")
    end)

    it("::ffff:a.b.c.d 合法映射形式 → 按 v4 校验", function()
        assert.is_true(helpers.is_valid_ip("::ffff:8.8.8.8"))
        assert.is_true(helpers.is_valid_ip("::FFFF:192.168.1.1")) -- 大写 hex
    end)

    it("映射形式内嵌非法 v4 仍拒绝", function()
        assert.is_false(helpers.is_valid_ip("::ffff:999.0.0.19"))
        assert.is_false(helpers.is_valid_ip("::ffff:1.2.3"))
    end)

    it("CIDR 一律拒绝(含映射形式)", function()
        assert.is_false(helpers.is_valid_ip("::ffff:10.0.0.0/8"))
        assert.is_false(helpers.is_valid_ip("10.0.0.0/8"))
    end)

    it("既有行为不回归", function()
        assert.is_true(helpers.is_valid_ip("1.2.3.4"))
        assert.is_false(helpers.is_valid_ip("256.1.1.1"))
        assert.is_true(helpers.is_valid_ip("fe80::1"))
        assert.is_false(helpers.is_valid_ip(""))
        assert.is_false(helpers.is_valid_ip(nil))
    end)
end)
