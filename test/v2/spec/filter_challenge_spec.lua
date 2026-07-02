describe("filter challenge flow", function()

    local filter, matcher_mod

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
        matcher_mod = require("matcher.init")
        matcher_mod.register("URI", require("matcher.uri").test)

        local s = ngx.shared.ip_reputation
        s:set("ip_rep:flagged_index", "[]")
        filter = require("plugin.filter.init")
    end)

    local function make_ctx(overrides)
        overrides = overrides or {}
        return {
            request = {
                uri = overrides.uri or "/test",
                remote_addr = overrides.remote_addr or "10.0.0.10",
                user_agent = overrides.user_agent or "Mozilla/5.0",
                scheme = "http",
            },
            match_cache = {},
            match_cache_size = 0,
            set_action = function(self, action_type, data)
                self.action_result = { type = action_type, data = data }
            end,
            set_data = function(self, key, val)
                if not self._data then self._data = {} end
                self._data[key] = val
            end,
            get_data = function(self, key)
                return self._data and self._data[key]
            end,
        }
    end

    it("passes through for management paths", function()
        local ctx = make_ctx({ uri = "/verynginx/dashboard" })
        filter.on_access(ctx)
        assert.is_nil(ctx.action_result)
    end)

    it("passes through for whitelisted IPs (empty whitelist = all IPs proceed)", function()
        local ctx = make_ctx({ uri = "/ok" })
        filter.on_access(ctx)
        assert.is_nil(ctx.action_result)
    end)

    it("blocks request when IP is flagged", function()
        local ip = "10.0.0.20"
        local rep = require("core.ip_reputation")
        rep.flag_ip(ip, 600)

        local ctx = make_ctx({
            uri = "/any-path",
            remote_addr = ip,
        })
        filter.on_access(ctx)
        assert.is_not_nil(ctx.action_result)
        assert.equals("block", ctx.action_result.type)
    end)

    it("clears flagged IP from cache after clear_ip", function()
        local ip = "10.0.0.21"
        local rep = require("core.ip_reputation")
        rep.flag_ip(ip, 600)

        local ctx = make_ctx({
            uri = "/any-path",
            remote_addr = ip,
        })
        filter.on_access(ctx)
        assert.equals("block", ctx.action_result.type)

        rep.clear_ip(ip)
        ctx2 = make_ctx({
            uri = "/any-path",
            remote_addr = ip,
        })
        filter.on_access(ctx2)
        -- No longer flagged, no rules match /any-path
        assert.is_nil(ctx2.action_result)
    end)

end)
