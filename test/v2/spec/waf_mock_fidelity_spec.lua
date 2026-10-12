-- -*- coding: utf-8 -*-
-- E-4: the dashboard rule tester's mock context must behave like
-- production. Before this fix it did no URL decoding (a tester case
-- ?q=%3Cscript%3E showed "not matching" while production blocks it — a
-- debugging trap) and repeated keys silently overwrote each other
-- (production returns a list per key).

describe("rule-tester mock fidelity (E-4)", function()
    local waf

    setup(function()
        waf = require("waf-rule-manager")
        -- Register the Args matcher exactly as the tester needs it
        require("matcher.init").register("Args", require("matcher.args").test)
    end)

    it("percent-decodes names and values", function()
        local args = waf._mock_uri_args("/x?q=%3Cscript%3E&a=1")
        assert.are_equal("<script>", args["q"])
        assert.are_equal("1", args["a"])
    end)

    it("decodes + as space", function()
        local args = waf._mock_uri_args("/x?q=a+b")
        assert.are_equal("a b", args["q"])
    end)

    it("repeated keys become lists (production semantics)", function()
        local args = waf._mock_uri_args("/x?a=1&a=2&a=3")
        assert.are.same({ "1", "2", "3" }, args["a"])
    end)

    it("valueless keys stay empty strings", function()
        local args = waf._mock_uri_args("/x?flag&b=2")
        assert.are_equal("", args["flag"])
        assert.are_equal("2", args["b"])
    end)

    it("no query string -> empty table", function()
        assert.are.same({}, waf._mock_uri_args("/x"))
        assert.are.same({}, waf._mock_uri_args(nil))
    end)

    it("test_rule now matches encoded payloads (was the debugging trap)", function()
        local rule = {
            id = "t", name = "t", enable = true, action = "log",
            matcher = { Args = { name_operator = "*", operator = "≈",
                                 value = "<script" } },
        }
        local results = waf.test_rule(rule, {
            { name = "encoded", uri = "/x?q=%3Cscript%3Ealert(1)%3C/script%3E",
              expected = true },
            { name = "clean",   uri = "/x?q=hello", expected = false },
        })
        assert.is_true(results[1].matched, "decoded payload must match")
        assert.is_true(results[1].passed)
        assert.is_true(results[2].passed)
    end)
end)
