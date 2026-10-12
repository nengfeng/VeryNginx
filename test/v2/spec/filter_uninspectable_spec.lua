-- plugin/filter synthetic uninspectable hit + body.on_error policy.
-- P1-4: requests whose body/args cannot be inspected (over limits, parse
-- failure) are recorded once under vn_body_uninspectable instead of the
-- masquerade where the first-priority Args rule claimed the hit.
-- body.on_error now REALLY controls the outcome (it used to be read only to
-- decide whether to log, so the advertised "fail_closed" never blocked):
--   fail_closed -> block (honest attribution, not a mislabelled rule)
--                  ONLY for suspicious causes (args overflow, parse failure)
--   skip        -> pass silently
--   log/match/unset -> observe (one synthetic hit, request passes) [default]
-- LARGE-BODY causes (body_too_large / body_truncated — ProcessPartial
-- scanned the affordable prefix) are observe-only under EVERY policy:
-- a >max_size body is legitimate traffic (uploads, imports) and is never
-- blocked for size alone.
-- P2: same-priority rules must evaluate in id order — Lua's table.sort is
-- unstable, so hit attribution used to depend on sort luck.

describe("filter uninspectable synthetic hit + tie-break", function()
    local filter, vn_config, config

    setup(function()
        package.preload["bit"] = function()
            local m = {}
            function m.band(a, b)
                local r, v = 0, 1
                while a > 0 or b > 0 do
                    if a % 2 == 1 and b % 2 == 1 then r = r + v end
                    a, b = math.floor(a / 2), math.floor(b / 2)
                    v = v * 2
                end
                return r
            end
            return m
        end
        require("matcher.init").register("URI", require("matcher.uri").test)
        filter = require("plugin.filter.init")
        vn_config = ngx.shared.vn_config
        config = require("core.config")
    end)

    local function ctx_with(err)
        return {
            request = { uri = "/t", remote_addr = "10.9.9.9", _body_error = err },
            action_result = nil,
            set_action = function(self, a, d) self.action_result = { type = a, data = d } end,
            has_decision = function(self) return self.action_result ~= nil end,
        }
    end

    local function hits_idx()
        return tonumber(vn_config:get("waf_recent_hits:idx") or 0)
    end

    -- Run fn with config.body.on_error temporarily set to val.
    local function with_on_error(val, fn)
        local created = false
        if not config.body then config.body = {}; created = true end
        local saved = config.body.on_error
        config.body.on_error = val
        local ok, err = pcall(fn)
        config.body.on_error = saved
        if created then config.body = nil end
        if not ok then error(err) end
    end

    it("observe (default): one synthetic hit, no block decision", function()
        assert.are.equal("vn_body_uninspectable", filter.UNINSPECTABLE_ID)
        local before = hits_idx()
        local ctx = ctx_with("body_too_large")
        assert.is_true(filter._record_uninspectable(ctx))
        assert.are_equal(before + 1, hits_idx())
        assert.is_nil(ctx.action_result, "observe must not set a block decision")
    end)

    it("no error -> no synthetic hit", function()
        local before = hits_idx()
        assert.is_false(filter._record_uninspectable(ctx_with(nil)))
        assert.are_equal(before, hits_idx())
    end)

    it("body.on_error=skip opts out entirely", function()
        with_on_error("skip", function()
            local before = hits_idx()
            local ctx = ctx_with("args_truncated")
            assert.is_false(filter._record_uninspectable(ctx))
            assert.are_equal(before, hits_idx())
            assert.is_nil(ctx.action_result)
        end)
    end)

    it("body.on_error=fail_closed blocks a suspicious cause with honest attribution", function()
        with_on_error("fail_closed", function()
            local before = hits_idx()
            local ctx = ctx_with("args_truncated")
            assert.is_true(filter._record_uninspectable(ctx))
            assert.are_equal(before + 1, hits_idx())
            assert.is_not_nil(ctx.action_result, "fail_closed must set a decision")
            assert.are_equal("block", ctx.action_result.type)
            assert.are_equal(403, ctx.action_result.data.code)
        end)
    end)

    it("fail_closed NEVER blocks a large body (body_too_large observes)", function()
        with_on_error("fail_closed", function()
            local before = hits_idx()
            local ctx = ctx_with("body_too_large")
            assert.is_true(filter._record_uninspectable(ctx))
            assert.are_equal(before + 1, hits_idx(), "must still record honestly")
            assert.is_nil(ctx.action_result,
                "size alone is legitimate traffic — never 403'd")
        end)
    end)

    it("fail_closed NEVER blocks a ProcessPartial prefix (body_truncated observes)", function()
        with_on_error("fail_closed", function()
            local before = hits_idx()
            local ctx = ctx_with("body_truncated")
            assert.is_true(filter._record_uninspectable(ctx))
            assert.are_equal(before + 1, hits_idx())
            assert.is_nil(ctx.action_result,
                "prefix was scanned; unscanned tail must not block")
        end)
    end)

    it("body.on_error=log explicitly observes (no block)", function()
        with_on_error("log", function()
            local before = hits_idx()
            local ctx = ctx_with("args_truncated")
            assert.is_true(filter._record_uninspectable(ctx))
            assert.are_equal(before + 1, hits_idx())
            assert.is_nil(ctx.action_result, "log must not block")
        end)
    end)

    it("fail_closed does not override a decision a rule already made", function()
        with_on_error("fail_closed", function()
            local before = hits_idx()
            local ctx = ctx_with("args_truncated")   -- blockable cause
            ctx.set_action(ctx, "accept")   -- e.g. an accept rule already fired
            assert.is_true(filter._record_uninspectable(ctx))
            assert.are_equal(before + 1, hits_idx())
            assert.are_equal("accept", ctx.action_result.type, "must not clobber the rule's action")
        end)
    end)

    it("split_rules: same priority evaluates in id order (both input orders)", function()
        local function mk(id, pri)
            return { id = id, name = id, enable = true, priority = pri,
                     category = "sqli", severity = "low", action = "log",
                     matcher = { URI = { operator = "=", value = "/" .. id } } }
        end
        local h1 = filter._split_rules({ mk("zeta", 10), mk("alpha", 10) })
        local h2 = filter._split_rules({ mk("alpha", 10), mk("zeta", 10) })
        assert.are.equal("alpha", h1[1].id, "input [zeta,alpha] must sort alpha first")
        assert.are.equal("alpha", h2[1].id, "input [alpha,zeta] must sort alpha first")
    end)

    it("split_rules: priority still dominates id order", function()
        local function mk(id, pri)
            return { id = id, name = id, enable = true, priority = pri,
                     category = "sqli", severity = "low", action = "log",
                     matcher = { URI = { operator = "=", value = "/" .. id } } }
        end
        local h = filter._split_rules({ mk("aaa", 50), mk("zzz", 10) })
        assert.are.equal("zzz", h[1].id, "priority 10 must come before priority 50")
    end)
end)
