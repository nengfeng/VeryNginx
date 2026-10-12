-- -*- coding: utf-8 -*-
-- @Disc    : matcher hot-path precompute (CRC + sorted conditions)

describe("matcher precompute", function()

    local matcher

    setup(function()
        matcher = require("matcher.init")
        matcher.register("URI", require("matcher.uri").test)
        matcher.register("UserAgent", require("matcher.ua").test)
    end)

    local function ctx()
        return { request = { uri = "/x" }, match_cache = {}, match_cache_size = 0 }
    end

    it("condition_order maps the registered matcher names (UserAgent, not UA)", function()
        local order = matcher.condition_order()
        assert.are.equal(4, order.UserAgent)
        assert.is_nil(order.UA)
    end)

    it("precompute sets _matcher_crc and _sorted_conditions", function()
        local md = { URI = { operator = "=", value = "/x" } }
        matcher.precompute(md)
        assert.is_not_nil(md._sorted_conditions)
        assert.are.equal(1, #md._sorted_conditions)
        assert.are.equal("URI", md._sorted_conditions[1].type)
        if ngx and ngx.crc32_short then
            assert.is_not_nil(md._matcher_crc, "crc should be precomputed")
        end
    end)

    it("precompute recurses into Composite sub-conditions", function()
        local md = {
            Composite = {
                operator = "AND",
                conditions = {
                    { Composite = { operator = "NOT",
                                    conditions = { { URI = { operator = "=", value = "/admin" } } } } },
                    { URI = { operator = "=", value = "/x" } },
                },
            },
        }
        matcher.precompute(md)
        local sub = md._sorted_conditions[1].cond.conditions
        -- nested NOT wrapper and sibling URI def both precomputed
        assert.is_not_nil(sub[1]._sorted_conditions, "NOT wrapper precomputed")
        assert.is_not_nil(sub[1].Composite.conditions[1]._sorted_conditions,
            "leaf inside NOT precomputed")
        assert.is_not_nil(sub[2]._sorted_conditions, "second AND branch precomputed")
    end)

    it("precompute is idempotent", function()
        local md = { URI = { operator = "=", value = "/x" } }
        matcher.precompute(md)
        local first = md._sorted_conditions
        matcher.precompute(md)
        assert.are.equal(first, md._sorted_conditions, "no re-sort on second call")
    end)

    it("evaluates identically before and after precompute", function()
        local md = { URI = { operator = "=", value = "/x" } }
        local before = matcher.test(md, ctx())
        matcher.precompute(md)
        assert.are.equal(before, matcher.test(md, ctx()))
        local c = { request = { uri = "/y" }, match_cache = {}, match_cache_size = 0 }
        local before2 = matcher.test({ URI = { operator = "=", value = "/x" } }, c)
        assert.is_false(matcher.test(md, c))
        assert.are.equal(before2, false)
    end)

    it("ignores underscore-prefixed metadata keys in the fallback sort", function()
        -- a def carrying metadata but NO _sorted_conditions must not treat
        -- the metadata key as a condition (which would fail the match)
        local md = { URI = { operator = "=", value = "/x" }, _matcher_crc = 12345 }
        assert.is_true(matcher.test(md, ctx()))
        local only_meta = { _matcher_crc = 12345 }
        assert.is_true(matcher.test(only_meta, ctx()),
            "metadata-only def has no real conditions")
    end)
end)
