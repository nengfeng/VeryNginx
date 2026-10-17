-- -*- coding: utf-8 -*-
-- A declared default is valid by definition.
--
-- alerting.webhook_url was declared as
--
--   leaf({ type = "string", default = "", pattern = "^https://" })
--
-- so the schema's own default failed the schema's own pattern, and every config
-- save logged
--
--   config normalize: alerting: alerting.webhook_url:
--   string does not match pattern '^https://'
--
-- The webhook is simply not configured on this host, and empty is what
-- DEFAULTS, send_webhook's early return, and the explicit save-time check all
-- treat as "no webhook". Only the pattern disagreed.
--
-- Widening the pattern was the first attempt and it cannot work: Lua patterns
-- have no alternation, so "^$|^https://" asks for the literal text "$|^https://"
-- and the empty string still fails. That is asserted below, because the mistake
-- is an easy one to repeat.

local cs = require "core.config_schema"

describe("a declared default is valid against its own pattern", function()

    it("admits the empty default of alerting.webhook_url", function()
        local schema = { type = "string", default = "", pattern = "^https://" }
        -- Absent key: normalize substitutes the default.
        local r = cs.normalize_node(schema, nil, { path = "alerting.webhook_url" })
        assert.are.equal("", r.value)
        assert.are.same({}, r.errors,
            "an unset webhook_url must not warn on every save")
    end)

    it("admits the default when it is present but empty", function()
        local schema = { type = "string", default = "", pattern = "^https://" }
        local r = cs.normalize_node(schema, "", { path = "alerting.webhook_url" })
        assert.are.equal("", r.value)
        assert.are.same({}, r.errors)
    end)

    it("still rejects a configured but invalid URL", function()
        -- The relaxation is scoped to the declared default. Anything the
        -- operator actually set is still held to the pattern.
        local schema = { type = "string", default = "", pattern = "^https://" }
        local r = cs.normalize_node(schema, "http://insecure.example/hook",
            { path = "alerting.webhook_url" })
        assert.is_true(#r.errors > 0, "a non-default bad value must still be rejected")
        assert.is_truthy(r.errors[1]:find("does not match pattern", 1, true))
    end)

    it("still accepts a valid URL", function()
        local schema = { type = "string", default = "", pattern = "^https://" }
        local r = cs.normalize_node(schema, "https://hooks.example/abc", {})
        assert.are.equal("https://hooks.example/abc", r.value)
        assert.are.same({}, r.errors)
    end)

    it("still rejects a bad value for a non-empty default", function()
        local schema = { type = "string", default = "https://x/", pattern = "^https://" }
        local r = cs.normalize_node(schema, "ftp://nope/", {})
        assert.is_true(#r.errors > 0)
        assert.are.equal("https://x/", r.value, "falls back to the default")
    end)

    it("documents why widening the pattern is not an option", function()
        -- Lua patterns have no alternation: "|" is a literal character, so the
        -- pattern that looks like "empty or https" requires the literal text.
        local schema = { type = "string", default = "", pattern = "^$|^https://" }
        local r = cs.normalize_node(schema, "", { path = "alerting.webhook_url" })
        assert.is_truthy(r.errors,
            "a Lua pattern cannot express 'empty OR https://'; the relaxation " ..
            "has to live in the validator, not the pattern")
    end)

    it("leaves non-string defaults alone", function()
        -- The exemption is string-only and exact-match only. Out-of-range
        -- integers still clamp to the bound and report, which is the
        -- pre-existing behaviour.
        local schema = { type = "integer", default = 5, min = 1, max = 10 }
        local r = cs.normalize_node(schema, 99, {})
        assert.is_true(#r.errors > 0, "integer bounds still apply")
        assert.are.equal(10, r.value, "clamped to max, as before")
    end)
end)