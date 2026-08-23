-- -*- coding: utf-8 -*-
-- Coverage for matcher/compare.lua's PRODUCTION invalid-regex branch:
-- when ngx.re.compile exists but the pattern fails to compile, match() must
-- be a fail-safe "no match" (both ≈ and !≈). This is the regression point for
-- AGENTS.md §10.13 — an invalid stored pattern used to raise through the old
-- find() fallback and 503 every evaluated request (critical-plugin policy).
--
-- The default spec_helper ngx stub ships ONLY re.find, so ordinary matcher
-- specs exercise the degraded fallback branch. Here we install a controlled
-- fake compile/match pair and RESTORE the original afterwards (ngx is
-- process-global — same hygiene as package.preload cleanup).

-- CI runs busted without --lpath; every spec prepends its own paths (this
-- file sorts BEFORE config_spec.lua, so it cannot rely on others doing it).
package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

local function install_fake_re(fail_patterns)
    local saved = ngx.re
    ngx.re = {
        compile = function(pattern)
            if fail_patterns[pattern] then return nil, "pcre_compile_failed" end
            return { __pat = pattern }
        end,
        match = function(subject, compiled)
            if subject:find(compiled.__pat, 1, true) then return {} end
            return nil
        end,
    }
    return saved
end

describe("compare.match invalid-regex fail-safe (production branch)", function()
    local saved_re

    before_each(function()
        saved_re = ngx.re
    end)

    after_each(function()
        ngx.re = saved_re -- restore the shared stub for later spec files
        package.loaded["matcher.compare"] = nil
        package.loaded["waf-rule-manager"] = nil
    end)

    it("invalid pattern ⇒ both operators fail-safe to false (no raise)", function()
        install_fake_re({ ["("] = true, ["(a+"] = true })
        package.loaded["matcher.compare"] = nil
        local compare = require "matcher.compare"

        assert.is_false(compare.match("/x", "≈", "("))
        assert.is_false(compare.match("/x", "!≈", "("))
        assert.is_false(compare.match("/x", "≈", "(a+"))
        assert.is_false(compare.match("/x", "!≈", "(a+"))
    end)

    it("valid patterns still evaluate through the compiled path", function()
        install_fake_re({})
        package.loaded["matcher.compare"] = nil
        local compare = require "matcher.compare"

        assert.is_true(compare.match("/admin/x", "≈", "/admin"))
        assert.is_false(compare.match("/user", "≈", "/admin"))
        assert.is_true(compare.match("/user", "!≈", "/admin"))
        assert.is_false(compare.match("/admin", "!≈", "/admin"))
    end)

    it("an invalid pattern does not poison subsequent valid ones (cache)", function()
        install_fake_re({ ["("] = true })
        package.loaded["matcher.compare"] = nil
        local compare = require "matcher.compare"

        assert.is_false(compare.match("/x", "≈", "("))   -- poisons nothing
        assert.is_true(compare.match("/ok", "≈", "/ok")) -- next compile still fine
        assert.is_false(compare.match("/x", "≈", "("))   -- stable, repeatable
    end)

    it("validate_rule rejects rules whose ≈ values fail compilation", function()
        install_fake_re({ ["(a+"] = true })
        package.loaded["waf-rule-manager"] = nil
        local waf = require "waf-rule-manager"

        local bad = { id = "re_bad_1", name = "bad", category = "sqli",
                      severity = "critical", action = "block",
                      matcher = { URI = { operator = "≈", value = "(a+" } } }
        local ok, err = waf.validate_rule(bad)
        assert.is_false(ok)
        assert.truthy(tostring(err):find("invalid regex"))

        local good = { id = "re_ok_1", name = "good", category = "sqli",
                       severity = "critical", action = "block",
                       matcher = { URI = { operator = "≈", value = "/login" } } }
        local ok2, err2 = waf.validate_rule(good)
        assert.is_true(ok2, tostring(err2))
    end)
end)
