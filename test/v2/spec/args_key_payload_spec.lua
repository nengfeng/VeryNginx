-- -*- coding: utf-8 -*-
-- E-1: parameter NAMES are attacker-controlled data too. Backends echo
-- names in error pages, search UIs and routing; before this fix every
-- attack rule (name_operator = "*") only scanned VALUES, so
-- ?<script>alert(1)</script>=1 walked past every Args rule.
-- With wildcard name matching, _test_args must also test the key against
-- the payload matcher. Conditions with an explicit name pattern keep
-- name-scoped semantics untouched.

package.path = "verynginx/?.lua;" .. package.path

describe("matcher.args key payload matching (E-1)", function()
    local args_mod

    setup(function()
        args_mod = require "matcher.args"
    end)

    local function ctx_uri(args)
        return {
            request = {},
            get_uri_args = function() return args end,
            get_body_args = function() return nil end,
        }
    end

    local function ctx_body(args)
        return {
            request = {},
            get_uri_args = function() return {} end,
            get_body_args = function() return args end,
        }
    end

    local wildcard = { name_operator = "*", operator = "≈", value = "<script" }

    it("wildcard condition matches a payload in the parameter NAME", function()
        assert.is_true(args_mod.test(wildcard,
            ctx_uri({ ["<script>alert(1)</script>"] = "1" })))
    end)

    it("wildcard condition still matches a payload in the VALUE", function()
        assert.is_true(args_mod.test(wildcard,
            ctx_uri({ q = "<script>alert(1)</script>" })))
    end)

    it("clean request stays unmatched", function()
        assert.is_false(args_mod.test(wildcard, ctx_uri({ q = "hello" })))
    end)

    it("body arg names (JSON flattened keys) are scanned too", function()
        assert.is_true(args_mod.test(wildcard,
            ctx_body({ ["<script>payload"] = "1" })))
        assert.is_false(args_mod.test(wildcard, ctx_body({ safe = "1" })))
    end)

    it("named condition keeps name-scoped semantics", function()
        local named = { name_operator = "=", name_value = "q",
                        operator = "≈", value = "<script" }
        -- key is not "q" -> condition doesn't apply at all (even though
        -- the key itself carries the payload)
        assert.is_false(args_mod.test(named, ctx_uri({ ["<script>"] = "1" })))
        -- key == q with value payload -> matches via the value path
        assert.is_true(args_mod.test(named, ctx_uri({ q = "<script>x" })))
    end)

    it("repeated-key lists are still scanned value-wise", function()
        assert.is_true(args_mod.test(wildcard,
            ctx_uri({ q = { "clean", "<script>x" } })))
    end)
end)
