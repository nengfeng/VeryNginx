-- -*- coding: utf-8 -*-
-- Tests for Frequency Rule ID Migration (Phase 0)
local mig = require "core.frequency.rule_id_migration"
local json = require "dkjson"

describe("m1 Migration: validate_legacy_id", function()
    it("accepts valid alphanumeric ID", function()
        local r = mig.validate_legacy_id("my_rule_1")
        assert.are.equal("valid", r.status)
        assert.are.equal("my_rule_1", r.id)
    end)

    it("accepts dots and dashes", function()
        local r = mig.validate_legacy_id("my.rule-1_test")
        assert.are.equal("valid", r.status)
    end)

    it("rejects empty string as missing", function()
        local r = mig.validate_legacy_id("")
        assert.are.equal("missing", r.status)
    end)

    it("rejects nil as missing", function()
        local r = mig.validate_legacy_id(nil)
        assert.are.equal("missing", r.status)
    end)

    it("rejects non-string as invalid", function()
        local r = mig.validate_legacy_id(42)
        assert.are.equal("invalid", r.status)
    end)

    it("rejects spaces", function()
        local r = mig.validate_legacy_id("my rule")
        assert.are.equal("invalid", r.status)
    end)

    it("rejects over-long ID (>128 bytes)", function()
        local r = mig.validate_legacy_id(string.rep("a", 129))
        assert.are.equal("invalid", r.status)
    end)

    it("rejects exactly 0 bytes as missing", function()
        local r = mig.validate_legacy_id("")
        assert.are.equal("missing", r.status)
    end)
end)

describe("m1 Migration: JCS canonicalization", function()
    it("sorts object keys lexicographically", function()
        local c = mig.jcs_canonicalize({ z = 1, a = 2, m = 3 })
        -- Keys sorted: a, m, z
        assert.truthy(c:find('"a":2'))
        assert.truthy(c:find('"m":3'))
        assert.truthy(c:find('"z":1'))
    end)

    it("handles nested objects", function()
        local c = mig.jcs_canonicalize({ b = { y = 1, x = 2 }, a = 3 })
        local inner = c:find('"x":2')
        assert.truthy(inner)
    end)

    it("handles arrays compactly", function()
        local c = mig.jcs_canonicalize({ "b", "a", "c" })
        assert.are.same('["b","a","c"]', c)
    end)
end)

describe("m1 Migration: b64url encode", function()
    it("encodes bytes without padding", function()
        -- 3 bytes -> 4 chars, no padding
        local e = mig.b64url_encode("\x00\x00\x00")
        assert.are.equal(4, #e)
        assert.falsy(e:find("="))
    end)

    it("encodes 32 bytes as 43 chars", function()
        local digest = string.rep("\xAB", 32)
        local e = mig.b64url_encode(digest)
        assert.are.equal(43, #e)
    end)

    it("uses URL-safe chars (- and _)", function()
        local e = mig.b64url_encode("\xfb\xff\xfe")
        assert.falsy(e:find("+"))
        assert.falsy(e:find("/"))
    end)
end)

describe("m1 Migration: generate_m1_id", function()
    it("produces deterministic output for same input", function()
        local rule1 = { enable = true, key = "ip", limit = 100, window = 60 }
        local rule2 = { enable = true, key = "ip", limit = 100, window = 60 }
        local reserved = {}
        local id1 = mig.generate_m1_id(1, rule1, "missing", 0, reserved)
        local id2 = mig.generate_m1_id(1, rule2, "missing", 0, reserved)
        assert.are.equal(id1, id2)
    end)

    it("produces 51-char output with freq_m1_ prefix", function()
        local rule = { enable = true, key = "ip", limit = 100, window = 60 }
        local reserved = {}
        local id = mig.generate_m1_id(1, rule, "missing", 0, reserved)
        assert.are.equal(51, #id)
        assert.truthy(id:find("^freq_m1_"))
    end)

    it("produces different IDs for different array indices", function()
        local rule = { enable = true, key = "ip", limit = 100, window = 60 }
        local reserved = {}
        local id1 = mig.generate_m1_id(1, rule, "missing", 0, reserved)
        reserved[id1] = true
        local id2 = mig.generate_m1_id(2, rule, "missing", 0, reserved)
        assert.are_not.equal(id1, id2)
    end)

    it("produces different IDs for different canonical rules", function()
        local rule1 = { enable = true, key = "ip", limit = 100, window = 60 }
        local rule2 = { enable = true, key = "ip", limit = 200, window = 60 }
        local reserved = {}
        local id1 = mig.generate_m1_id(1, rule1, "missing", 0, reserved)
        reserved[id1] = true
        local id2 = mig.generate_m1_id(2, rule2, "missing", 0, reserved)
        assert.are_not.equal(id1, id2)
    end)

    it("strips the id field before canonicalization", function()
        local rule_with_id = { id = "foo", enable = true, key = "ip", limit = 100, window = 60 }
        local rule_without = { enable = true, key = "ip", limit = 100, window = 60 }
        local reserved = {}
        local id1 = mig.generate_m1_id(1, rule_with_id, "missing", 0, reserved)
        local id2 = mig.generate_m1_id(1, rule_without, "missing", 0, reserved)
        assert.are.equal(id1, id2)
    end)

    it("produces different IDs for different old_id_marker (missing vs present)", function()
        local rule = { enable = true, key = "ip", limit = 100, window = 60 }
        local reserved = {}
        local id_missing = mig.generate_m1_id(1, rule, "missing", 0, reserved)
        reserved[id_missing] = true
        local id_present = mig.generate_m1_id(2, rule, "present:same_id", 1, reserved)
        assert.are_not.equal(id_missing, id_present)
    end)

    it("handles collision attempt by incrementing", function()
        local rule = { enable = true, key = "ip", limit = 100, window = 60 }
        local reserved = {}
        local first_id = mig.generate_m1_id(1, rule, "missing", 0, reserved)
        reserved[first_id] = true
        -- Different index with same marker will produce a different ID
        local second_id = mig.generate_m1_id(2, rule, "missing", 0, reserved)
        assert.are_not.equal(first_id, second_id)
    end)
end)

describe("m1 Migration: validate", function()
    it("accepts all rules with unique valid IDs", function()
        local rules = {
            { id = "rule_a", enable = true },
            { id = "rule_b", enable = true },
        }
        local ok, err = mig.validate(rules)
        assert.is_true(ok)
    end)

    it("rejects rules with missing IDs", function()
        local rules = {
            { id = "rule_a", enable = true },
            { enable = true },
        }
        local ok, err = mig.validate(rules)
        assert.is_false(ok)
    end)

    it("rejects rules with duplicate IDs", function()
        local rules = {
            { id = "same", enable = true },
            { id = "same", enable = true },
        }
        local ok, err = mig.validate(rules)
        assert.is_false(ok)
    end)
end)
