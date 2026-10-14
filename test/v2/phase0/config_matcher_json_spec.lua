-- vim: filetype=lua
--
-- Regression pins for the matcherJson alias bug.
--
-- The frequency editor and the template library carry the matcher as
-- `matcherJson`, a JSON *string*. Nothing downstream consumed it:
-- compile_runtime_snapshot() resolved only `rule.matcher`, validate_rule()
-- validated only `rule.matcher`, and matcher.resolve() looks at
-- `_matcher_def` / `rule.matcher`. A rule holding just the string resolved to
-- nil, the frequency plugin skipped it, and the skip was silent — so a rule
-- created from a template looked configured in the panel and matched nothing,
-- forever. Verified on production: a temporary rule created the template way
-- (limit 2/60s, exact URI matcher) did not fire across five requests, while the
-- same rule sent with `matcher` returned 429 on the third request.
--
-- The expansion has to happen BEFORE validation, not after: validate_rule() is
-- what rejects malformed IPs and CIDR in frequency matchers, so expanding
-- later would let a caller bypass those constraints by hiding the matcher in
-- the string field.

describe("config matcherJson expansion", function()
    local config = require "core.config"

    local function rule_with(fields)
        return { rule = { frequency_limit = { fields } } }
    end

    it("expands matcherJson into a matcher table", function()
        local cfg = rule_with({
            id = "freq_a",
            matcherJson = '{"URI":{"operator":"≈","value":"/login"}}',
        })
        config.expand_matcher_json(cfg)
        assert.are.equal("table", type(cfg.rule.frequency_limit[1].matcher))
        assert.are.equal("/login", cfg.rule.frequency_limit[1].matcher.URI.value)
    end)

    it("keeps matcherJson for the editor round-trip", function()
        local raw = '{"URI":{"operator":"≈","value":"/api/"}}'
        local cfg = rule_with({ id = "freq_b", matcherJson = raw })
        config.expand_matcher_json(cfg)
        assert.are.equal(raw, cfg.rule.frequency_limit[1].matcherJson)
    end)

    it("an explicit matcher wins over matcherJson", function()
        local explicit = { URI = { operator = "≈", value = "/explicit" } }
        local cfg = rule_with({
            id = "freq_c",
            matcher = explicit,
            matcherJson = '{"URI":{"operator":"≈","value":"/json"}}',
        })
        config.expand_matcher_json(cfg)
        assert.are.equal("/explicit", cfg.rule.frequency_limit[1].matcher.URI.value)
    end)

    it("leaves an undecodable matcherJson alone so the operator can see it", function()
        local cfg = rule_with({ id = "freq_d", matcherJson = "{not json" })
        config.expand_matcher_json(cfg)
        assert.is_nil(cfg.rule.frequency_limit[1].matcher)
        assert.are.equal("{not json", cfg.rule.frequency_limit[1].matcherJson)
    end)

    it("ignores blank and non-string matcherJson", function()
        local cfg = rule_with({ id = "freq_e", matcherJson = "" })
        local cfg2 = rule_with({ id = "freq_f", matcherJson = 42 })
        config.expand_matcher_json(cfg)
        config.expand_matcher_json(cfg2)
        assert.is_nil(cfg.rule.frequency_limit[1].matcher)
        assert.is_nil(cfg2.rule.frequency_limit[1].matcher)
    end)

    it("covers every rule group, not just frequency_limit", function()
        local cfg = { rule = {
            rate_limit   = { { id = "r1", matcherJson = '{"URI":{"operator":"≈","value":"/a"}}' } },
            frequency_limit = { { id = "r2", matcherJson = '{"URI":{"operator":"≈","value":"/b"}}' } },
        } }
        config.expand_matcher_json(cfg)
        assert.are.equal("/a", cfg.rule.rate_limit[1].matcher.URI.value)
        assert.are.equal("/b", cfg.rule.frequency_limit[1].matcher.URI.value)
    end)

    it("is idempotent — running twice changes nothing", function()
        local cfg = rule_with({
            id = "freq_g",
            matcherJson = '{"URI":{"operator":"≈","value":"/x"}}',
        })
        config.expand_matcher_json(cfg)
        local first = cfg.rule.frequency_limit[1].matcher
        config.expand_matcher_json(cfg)
        assert.are.equal(first, cfg.rule.frequency_limit[1].matcher)
    end)

    it("tolerates a config with no rule section", function()
        assert.has_no.errors(function() config.expand_matcher_json({}) end)
        assert.has_no.errors(function() config.expand_matcher_json(nil) end)
    end)
end)
