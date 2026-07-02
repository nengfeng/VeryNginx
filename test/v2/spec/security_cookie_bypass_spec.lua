describe("security: split_rules architecture", function()

    local filter

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
        filter = require("plugin.filter.init")
    end)

    it("block rules are evaluated before cookie check (structural test)", function()
        -- The on_access function evaluates hard_block_rules (stage 1) FIRST,
        -- then checks cookie (stage 2). This is verified by testing that
        -- an IP with is_flagged=true gets blocked before any cookie check.
        local ip = "10.0.0.40"
        local rep = require("core.ip_reputation")
        rep.flag_ip(ip, 600)

        -- Even with a cookie set, the IP should be blocked by the flagged check
        -- which happens before the cookie check
        ngx.var = ngx.var or {}
        ngx.var.http_cookie = "verynginx_sign_javascript=somehash"

        local ctx = {
            request = {
                uri = "/test",
                remote_addr = ip,
                user_agent = "Mozilla/5.0",
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

        filter.on_access(ctx)
        assert.is_not_nil(ctx.action_result)
        assert.equals("block", ctx.action_result.type)
    end)

end)
