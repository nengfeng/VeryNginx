-- -*- coding: utf-8 -*-
-- Tests for frequency rule template library.

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end

describe("frequency_templates", function()
    before_each(function()
        package.loaded["core.frequency_templates"] = nil
    end)

    it("list() returns all templates with metadata", function()
        local tpl = require "core.frequency_templates"
        local list = tpl.list()
        assert.truthy(#list > 0)
        for _, t in ipairs(list) do
            assert.truthy(t.name)
            assert.truthy(t.label)
            assert.truthy(t.description)
        end
    end)

    it("list() includes known scenarios", function()
        local tpl = require "core.frequency_templates"
        local list = tpl.list()
        local names = {}
        for _, t in ipairs(list) do names[t.name] = true end
        assert.truthy(names.login_bruteforce)
        assert.truthy(names.api_abuse)
        assert.truthy(names.crawler)
        assert.truthy(names.global_cc)
        assert.truthy(names.sensitive_api)
    end)

    it("apply() returns a valid rule with template defaults", function()
        local tpl = require "core.frequency_templates"
        local rule = tpl.apply("login_bruteforce")
        assert.truthy(rule)
        assert.are.equal("freq_login_bruteforce", rule.id)
        assert.are.equal("ip", rule.key)
        assert.are.equal(5, rule.limit)
        assert.are.equal(60, rule.window)
        assert.are.equal(429, rule.code)
    end)

    it("apply() applies overrides", function()
        local tpl = require "core.frequency_templates"
        local rule = tpl.apply("login_bruteforce", { limit = 10, window = 120 })
        assert.are.equal(10, rule.limit)
        assert.are.equal(120, rule.window)
        -- Non-overridden fields preserved.
        assert.are.equal("ip", rule.key)
    end)

    it("apply() returns error for unknown template", function()
        local tpl = require "core.frequency_templates"
        local rule, err = tpl.apply("nonexistent")
        assert.is_nil(rule)
        assert.truthy(err)
    end)

    it("apply() deep-copies so mutation does not affect template", function()
        local tpl = require "core.frequency_templates"
        local rule1 = tpl.apply("crawler")
        rule1.limit = 999
        local rule2 = tpl.apply("crawler")
        assert.are.equal(30, rule2.limit)
    end)

    it("get() returns full template with rule", function()
        local tpl = require "core.frequency_templates"
        local t = tpl.get("api_abuse")
        assert.truthy(t)
        assert.are.equal("api_abuse", t.name)
        assert.truthy(t.label)
        assert.truthy(t.rule)
        assert.are.equal(60, t.rule.limit)
    end)

    it("get() returns nil for unknown template", function()
        local tpl = require "core.frequency_templates"
        local t = tpl.get("nonexistent")
        assert.is_nil(t)
    end)
end)
