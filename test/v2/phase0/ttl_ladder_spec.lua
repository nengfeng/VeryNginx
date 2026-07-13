-- Design §6.6 TTL ladder unit tests.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;"
    .. package.path

if not _G.ngx then _G.ngx = {} end
_G.ngx.time = function() return 1700000000 end

local ladder = require "core.kernel_blocking.ttl_ladder"

describe("TTL ladder §6.6", function()
    it("builds 300→600→1800 for CC defaults", function()
        local steps = ladder.build_steps(300, 1800)
        assert.are.equal(3, #steps)
        assert.are.equal(300, steps[1])
        assert.are.equal(600, steps[2])
        assert.are.equal(1800, steps[3])
    end)

    it("respects configured steps and caps at max", function()
        local steps = ladder.build_steps(300, 1800, { 300, 900, 99999 })
        assert.are.equal(300, steps[1])
        assert.are.equal(900, steps[2])
        assert.are.equal(1800, steps[3])
    end)

    it("first install uses tier 1", function()
        local steps = ladder.build_steps(300, 1800)
        local plan = ladder.plan({
            steps = steps, max_ttl = 1800, promotion_count = 0,
            now = 1000,
        })
        assert.is_true(plan.extends)
        assert.are.equal(300, plan.ttl)
        assert.are.equal(1, plan.tier)
        assert.are.equal(1, plan.next_promotion_count)
        assert.are.equal("initial_promotion", plan.reason)
    end)

    it("renew escalates 300→600→1800 without shortening", function()
        local steps = ladder.build_steps(300, 1800)
        local p1 = ladder.plan({
            steps = steps, max_ttl = 1800, promotion_count = 0, now = 1000,
        })
        assert.are.equal(300, p1.ttl)

        -- Still active with remaining 250s; next rung 600 extends.
        local p2 = ladder.plan({
            steps = steps, max_ttl = 1800, promotion_count = 1,
            existing_expires_at = 1000 + 250, now = 1000,
        })
        assert.is_true(p2.extends)
        assert.are.equal(600, p2.ttl)
        assert.are.equal(2, p2.tier)
        assert.are.equal("stepped_renewal", p2.reason)

        local p3 = ladder.plan({
            steps = steps, max_ttl = 1800, promotion_count = 2,
            existing_expires_at = 1000 + 100, now = 1000,
        })
        assert.is_true(p3.extends)
        assert.are.equal(1800, p3.ttl)
        assert.are.equal(3, p3.tier)

        -- Already at max full remaining: no extension
        local p4 = ladder.plan({
            steps = steps, max_ttl = 1800, promotion_count = 3,
            existing_expires_at = 1000 + 1800, now = 1000,
        })
        assert.is_false(p4.extends)
        assert.are.equal("no_extension", p4.reason)
    end)

    it("never exceeds max_ttl", function()
        local steps = ladder.build_steps(300, 900)
        local plan = ladder.plan({
            steps = steps, max_ttl = 900, promotion_count = 5, now = 0,
        })
        assert.truthy(plan.ttl <= 900)
    end)

    it("steps_for_policy uses flag_duration for scanner", function()
        local steps, max_ttl = ladder.steps_for_policy("scanner", {
            scanner = { max_ttl = 86400 },
        }, { flag_duration = 600 })
        assert.are.equal(600, steps[1])
        assert.are.equal(86400, max_ttl)
        assert.truthy(steps[#steps] == 86400)
    end)

    it("steps_for_policy uses cc.ttl for CC", function()
        local steps = ladder.steps_for_policy("cc", {
            cc = { ttl = 300, max_ttl = 1800 },
        }, {})
        assert.are.equal(300, steps[1])
        assert.are.equal(600, steps[2])
        assert.are.equal(1800, steps[3])
    end)
end)
