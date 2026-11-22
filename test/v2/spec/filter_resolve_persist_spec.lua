-- -*- coding: utf-8 -*-
-- Regression guard: split_rules() at rule-load time persists the resolved
-- matcher definition on the worker-local rule object, so the per-request
-- matcher.resolve(rule) in evaluate_rules() is a single table read instead
-- of re-walking config.matcher by name on every rule of every request.

describe("filter split_rules persists resolved matcher", function()
    local filter, matcher

    setup(function()
        package.preload["bit"] = package.preload["bit"] or function()
            local m = {}
            function m.band() return 0 end
            return m
        end
        matcher = require("matcher.init")
        filter = require("plugin.filter.init")
    end)

    it("sets _matcher_def on named-matcher rules after split", function()
        local config = require("core.config")
        local saved = config.matcher
        config.matcher = { my_test_rule_def = { URI = { operator = "=", value = "/x" } } }
        local rules = {
            { id = "r1", enable = true, action = "log", matcher = "my_test_rule_def", priority = 1 },
        }
        local hard = filter._split_rules(rules)
        assert.is_equal(1, #hard)
        assert.is_not_nil(hard[1]._matcher_def)
        assert.is_equal("/x", hard[1]._matcher_def.URI.value)
        config.matcher = saved
    end)

    it("sets _matcher_def on inline-table matcher rules", function()
        local rules = {
            { id = "r2", enable = true, action = "block", matcher = { URI = { operator = "=", value = "/y" } } },
        }
        local hard = filter._split_rules(rules)
        assert.is_equal(1, #hard)
        assert.is_not_nil(hard[1]._matcher_def)
        assert.is_equal("/y", hard[1]._matcher_def.URI.value)
    end)
end)
