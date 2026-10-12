-- -*- coding: utf-8 -*-
-- matcher/args.lua on_body_error policy (P1-4, direction iii):
-- the GLOBAL body.on_error no longer fans out to every Args condition.
-- Previously an uninspectable body (over max_size / max_args, parse
-- failure) made EVERY Args rule "match", so whichever rule sorted first
-- claimed the hit — usually vn_sqli_0001, pri=10 — mislabelling large
-- legitimate uploads as SQLi and 403ing them on default installs.
-- Now only conditions that EXPLICITLY set on_body_error keep fail-closed
-- semantics; the filter records one honest synthetic hit
-- (vn_body_uninspectable) for the uninspectable request instead.

package.path = "verynginx/?.lua;" .. package.path

describe("matcher.args on_body_error policy", function()
    local args_mod

    setup(function()
        args_mod = require "matcher.args"
    end)

    -- args.test always consults URI args first, then lazily the body.
    local function ctx(err)
        return {
            request = { _body_error = err },
            get_uri_args = function() return {} end,
            get_body_args = function() return nil end,
        }
    end

    local function cond(policy)
        local c = { name_operator = "*", operator = "≈", value = "union" }
        if policy then c.on_body_error = policy end
        return c
    end

    it("plain condition does NOT fire on an uninspectable body (no fan-out)", function()
        assert.is_false(args_mod.test(cond(), ctx("body_too_large")))
        assert.is_false(args_mod.test(cond(), ctx("args_truncated")))
    end)

    it("per-condition fail_closed keeps firing", function()
        assert.is_true(args_mod.test(cond("fail_closed"), ctx("body_too_large")))
    end)

    it("per-condition match keeps firing", function()
        assert.is_true(args_mod.test(cond("match"), ctx("args_truncated")))
    end)

    it("per-condition skip stays open", function()
        assert.is_false(args_mod.test(cond("skip"), ctx("body_too_large")))
    end)

    it("uri-args truncation follows the same per-condition policy", function()
        local c = {
            request = { _uri_args_error = "args_truncated" },
            get_uri_args = function() return {} end,
            get_body_args = function() return nil end,
        }
        assert.is_false(args_mod.test(cond(), c))
        assert.is_true(args_mod.test(cond("fail_closed"), c))
    end)

    it("normal matching unaffected when nothing failed", function()
        local c = {
            request = {},
            get_uri_args = function() return { q = "1 union select 1" } end,
        }
        assert.is_true(args_mod.test(cond(), c))
    end)
end)
