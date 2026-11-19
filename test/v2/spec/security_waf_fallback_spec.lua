-- Security: the last-resort WAF fallback must be able to match.
--
-- plugin/filter/rules.lua is used when waf-rules.json and the shipped factory
-- file are both unavailable. Its rules used to reference named matchers
-- ("attack_sqli") while config.matcher is empty in that scenario, so every
-- fallback rule resolved to nil and the WAF silently served no rules. The
-- fallback now inlines the matcher definitions.

describe("security: WAF fallback rules are inline and matchable", function()

    local rules_mod

    setup(function()
        package.preload["waf-rule-manager"] = function()
            return { load_rules = function() return nil end }
        end
        package.loaded["plugin.filter.rules"] = nil
        rules_mod = require("plugin.filter.rules")
    end)

    teardown(function()
        package.preload["waf-rule-manager"] = nil
        package.loaded["plugin.filter.rules"] = nil
    end)

    it("returns fallback rules with inline matcher tables", function()
        local rules = rules_mod.load_rules()
        assert.is_true(#rules > 0)
        for _, r in ipairs(rules) do
            assert.equals("table", type(r.matcher),
                "fallback rule " .. tostring(r.id) .. " must not rely on config.matcher")
        end
    end)

    it("keeps the documented fallback actions", function()
        local rules = rules_mod.load_rules()
        local seen_block, seen_challenge = false, false
        for _, r in ipairs(rules) do
            if r.action == "block" then seen_block = true end
            if r.action == "challenge" then seen_challenge = true end
        end
        assert.is_true(seen_block)
        assert.is_true(seen_challenge)
    end)

end)
