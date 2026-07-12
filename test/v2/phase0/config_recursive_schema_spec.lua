-- -*- coding: utf-8 -*-
-- Tests for the recursive config schema walker (Phase 0 / kernel_ip_blocking)
local cs = require "core.config_schema"

describe("config_schema.normalize_node", function()
    -- Leaf field: string with default
    describe("leaf string", function()
        local schema = { type = "string", default = "hello" }
        it("fills default when nil", function()
            local r = cs.normalize_node(schema, nil, {})
            assert.are.equal("hello", r.value)
            assert.are.same({}, r.errors)
        end)
        it("returns user value when valid", function()
            local r = cs.normalize_node(schema, "world", {})
            assert.are.equal("world", r.value)
            assert.are.same({}, r.errors)
        end)
        it("rejects non-string with default fallback", function()
            local r = cs.normalize_node(schema, 42, { path = "foo" })
            assert.are.equal("hello", r.value)
            assert.are.equal(1, #r.errors)
        end)
    end)

    -- Leaf field: integer with min/max
    describe("leaf integer", function()
        local schema = { type = "integer", default = 10, min = 1, max = 100 }
        it("accepts value in range", function()
            local r = cs.normalize_node(schema, 50, {})
            assert.are.equal(50, r.value)
        end)
        it("clamps value below min", function()
            local r = cs.normalize_node(schema, -5, { path = "x" })
            assert.are.equal(1, r.value)
            assert.are.equal(1, #r.errors)
        end)
        it("clamps value above max", function()
            local r = cs.normalize_node(schema, 999, { path = "x" })
            assert.are.equal(100, r.value)
            assert.are.equal(1, #r.errors)
        end)
        it("rejects non-number", function()
            local r = cs.normalize_node(schema, "abc", { path = "x" })
            assert.are.equal(10, r.value)  -- default fallback
            assert.is_true(#r.errors >= 1)
        end)
    end)

    -- Leaf: enum
    describe("leaf enum", function()
        local schema = { type = "string", default = "a", enum = { "a", "b", "c" } }
        it("accepts valid enum value", function()
            local r = cs.normalize_node(schema, "b", {})
            assert.are.equal("b", r.value)
        end)
        it("rejects invalid enum value", function()
            local r = cs.normalize_node(schema, "z", { path = "m" })
            assert.are.equal("a", r.value)  -- default
            assert.are.equal(1, #r.errors)
        end)
    end)

    -- Leaf: boolean
    describe("leaf boolean", function()
        local schema = { type = "boolean", default = false }
        it("accepts true", function()
            local r = cs.normalize_node(schema, true, {})
            assert.is_true(r.value)
        end)
        it("rejects non-boolean", function()
            local r = cs.normalize_node(schema, 1, { path = "b" })
            assert.is_false(r.value)
            assert.are.equal(1, #r.errors)
        end)
    end)

    -- Leaf: array
    describe("leaf array", function()
        local schema = { type = "array", default = {}, items = "string", unique_items = true }
        it("accepts valid array", function()
            local r = cs.normalize_node(schema, { "a", "b" }, {})
            assert.are.same({ "a", "b" }, r.value)
        end)
        it("rejects non-string items in string array", function()
            local r = cs.normalize_node(schema, { "a", 42 }, { path = "arr" })
            assert.are.same({ "a", 42 }, r.value)   -- preserves but flags
            -- type error recorded on path.arr[2]
        end)
        it("rejects duplicate when unique_items", function()
            local r = cs.normalize_node(schema, { "a", "a" }, { path = "arr" })
            assert.is_true(#r.errors >= 1)
        end)
        it("accepts nil (default to [])", function()
            local r = cs.normalize_node(schema, nil, {})
            assert.are.same({}, r.value)
        end)
    end)

    -- Recursive object with children
    describe("recursive object", function()
        local schema = {
            type = "object",
            default = { x = 1, y = "hi" },
            children = {
                x = { type = "integer", default = 1, min = 0 },
                y = { type = "string", default = "hi" },
            },
        }
        it("fills all defaults when nil", function()
            local r = cs.normalize_node(schema, nil, {})
            assert.are.equal(1, r.value.x)
            assert.are.equal("hi", r.value.y)
        end)
        it("preserves valid partial override", function()
            local r = cs.normalize_node(schema, { x = 5 }, {})
            assert.are.equal(5, r.value.x)
            assert.are.equal("hi", r.value.y)  -- defaulted
        end)
        it("validates nested types", function()
            local r = cs.normalize_node(schema, { x = -1, y = 3 }, { path = "root" })
            assert.are.equal(0, r.value.x)    -- clamped to min
            assert.are.equal("hi", r.value.y) -- replaced with default
            assert.are.equal(2, #r.errors)
        end)
        it("preserves unknown fields by default", function()
            local r = cs.normalize_node(schema, { x = 2, foo = "bar" }, { path = "p" })
            assert.are.equal("bar", r.value.foo)
        end)
        it("rejects unknown fields when reject_unknown=true", function()
            local schema2 = {
                type = "object",
                default = {},
                reject_unknown = true,
                children = { a = { type = "string", default = "x" } },
            }
            local r = cs.normalize_node(schema2, { a = "b", evil = true }, { path = "p" })
            assert.is_nil(r.value.evil)
            assert.are.equal(1, #r.errors)
            assert.truthy(r.errors[1]:find("unknown"))
        end)
    end)

    -- Nested deep structure (same shape as kernel_ip_blocking)
    describe("deep nested", function()
        local schema = {
            type = "object",
            default = {
                enabled = false,
                max_ttl = 86400,
                scanner = { enabled = true, min_hard_blocks = 3 },
            },
            reject_unknown = true,
            children = {
                enabled   = { type = "boolean", default = false },
                max_ttl   = { type = "integer", default = 86400, min = 60, max = 604800 },
                scanner   = {
                    type = "object",
                    default = { enabled = true, min_hard_blocks = 3 },
                    children = {
                        enabled        = { type = "boolean", default = true },
                        min_hard_blocks = { type = "integer", default = 3, min = 1, max = 100 },
                    },
                    reject_unknown = true,
                },
            },
        }
        it("fully defaults when nil", function()
            local r = cs.normalize_node(schema, nil, {})
            assert.is_false(r.value.enabled)
            assert.are.equal(86400, r.value.max_ttl)
            assert.is_true(r.value.scanner.enabled)
            assert.are.equal(3, r.value.scanner.min_hard_blocks)
        end)
        it("merges partial config correctly", function()
            local r = cs.normalize_node(schema, {
                max_ttl = 3600,
                scanner = { min_hard_blocks = 5 },
            }, {})
            assert.is_false(r.value.enabled)   -- still default
            assert.are.equal(3600, r.value.max_ttl)
            assert.are.equal(5, r.value.scanner.min_hard_blocks)
            assert.is_true(r.value.scanner.enabled) -- preserved from default
        end)
        it("reject unknown leaf in deep nested", function()
            local r = cs.normalize_node(schema, {
                scanner = { evil_field = true },
            }, { path = "kb" })
            assert.is_nil(r.value.scanner.evil_field)
            assert.are.equal(1, #r.errors)
            assert.truthy(r.errors[1]:find("unknown"))
        end)
    end)
end)
