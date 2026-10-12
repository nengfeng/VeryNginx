-- plugin/filter synthetic uninspectable hit + deterministic tie-break.
-- P1-4: requests whose body/args cannot be inspected (over limits, parse
-- failure) are recorded once under vn_body_uninspectable instead of the
-- masquerade where the first-priority Args rule claimed the hit.
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
        return { request = { uri = "/t", remote_addr = "10.9.9.9", _body_error = err } }
    end

    local function hits_idx()
        return tonumber(vn_config:get("waf_recent_hits:idx") or 0)
    end

    it("records exactly one synthetic hit for an uninspectable body", function()
        assert.are.equal("vn_body_uninspectable", filter.UNINSPECTABLE_ID)
        local before = hits_idx()
        assert.is_true(filter._record_uninspectable(ctx_with("body_too_large")))
        assert.are_equal(before + 1, hits_idx())
    end)

    it("no error -> no synthetic hit", function()
        local before = hits_idx()
        assert.is_false(filter._record_uninspectable(ctx_with(nil)))
        assert.are_equal(before, hits_idx())
    end)

    it("body.on_error=skip opts out entirely", function()
        local created = false
        if not config.body then config.body = {}; created = true end
        local saved = config.body.on_error
        config.body.on_error = "skip"
        local before = hits_idx()
        local ok, res = pcall(filter._record_uninspectable, ctx_with("args_truncated"))
        config.body.on_error = saved
        if created then config.body = nil end
        assert.is_true(ok)
        assert.is_false(res)
        assert.are_equal(before, hits_idx())
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
