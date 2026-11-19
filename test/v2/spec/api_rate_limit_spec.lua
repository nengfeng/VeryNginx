-- api.rate_limit.allow must fail closed when the shared counter cannot be
-- incremented. Returning true there would let an attacker who exhausts
-- vn_rate_limit bypass every API/login rate limit at once.

describe("api.rate_limit fail-closed", function()

    local rate_limit, saved

    setup(function()
        rate_limit = require("api.rate_limit")
        saved = ngx.shared.vn_rate_limit
    end)

    teardown(function()
        ngx.shared.vn_rate_limit = saved
    end)

    it("returns false when incr fails", function()
        ngx.shared.vn_rate_limit = {
            incr = function() return nil, "no memory" end,
        }
        assert.is_false(rate_limit.allow("key", 10, 60))
    end)

    it("returns true under the limit and false over it", function()
        local n = 0
        ngx.shared.vn_rate_limit = {
            incr = function() n = n + 1; return n end,
        }
        assert.is_true(rate_limit.allow("key", 2, 60))
        assert.is_true(rate_limit.allow("key", 2, 60))
        assert.is_false(rate_limit.allow("key", 2, 60))
    end)

    it("still allows when the shared dict is absent (test rigs)", function()
        ngx.shared.vn_rate_limit = nil
        assert.is_true(rate_limit.allow("key", 10, 60))
    end)

end)
