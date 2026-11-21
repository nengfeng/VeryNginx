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

    describe("rate-limit exceed", function()
        local dk = require "dkjson"
        local shared = nil

        -- Inject a rate-limited rule straight into the shared-dict cache
        -- (meta + chunk + version) instead of save_rules, which writes the
        -- disk file. The version must differ from the filter module's
        -- cached _rule_cache.version (else get_cached_rules takes the fast
        -- path and returns the previously cached rules) and be unique per
        -- test for the same reason across this file's tests.
        local function inject_rate_rule(id, rate_action, version)
            shared = ngx.shared.vn_config
            shared:flush_all()
            local rule = {
                id = id,
                name = "rate " .. id,
                category = "sqli",
                severity = "high",
                action = "block",
                enable = true,
                matcher = { URI = { operator = "=", value = "/" .. id } },
                rate_limit = { enable = true, max_hits = 3, window = 60, action = rate_action },
            }
            shared:set("waf_rules:meta", dk.encode({
                version = version, timestamp = ngx.time(), chunk_count = 1,
            }))
            shared:set("waf_rules:chunk:1", dk.encode({ rules = { rule }, count = 1 }))
            shared:set("waf_rules_version", version)
            return rule
        end
        -- Restore the "no rules cached" state so other specs are unaffected.
        local function cleanup(ids, slots)
            shared:delete("waf_rules_version")
            shared:delete("waf_rules:meta")
            shared:delete("waf_rules:chunk:1")
            for _, id in ipairs(ids) do
                for _, slot in ipairs(slots) do
                    shared:delete("waf_rate_limit:" .. id .. ":" .. slot)
                    shared:delete("waf_rule_stats:" .. id .. ":today:" .. os.date("!%Y%m%d"))
                end
            end
        end

        it("action=block: an exceeded request is blocked with 403", function()
            inject_rate_rule("rl_blk", "block", 990)
            local slot = math.floor(ngx.time() / 60)
            -- check_rate_limit's incr reads the counter table: pre-seed
            -- max_hits so the post-increment count is max_hits + 1.
            shared:incr("waf_rate_limit:rl_blk:" .. slot, 3, 0, 60)
            local ctx = make_ctx({ uri = "/rl_blk" })
            filter.on_access(ctx)
            assert.is_not_nil(ctx.action_result)
            assert.equals("block", ctx.action_result.type)
            assert.equals(403, ctx.action_result.data.code)
            cleanup({ "rl_blk" }, { slot })
        end)

        it("action=log: an exceeded request passes through and the hit is recorded", function()
            inject_rate_rule("rl_log", "log", 991)
            local slot = math.floor(ngx.time() / 60)
            shared:incr("waf_rate_limit:rl_log:" .. slot, 3, 0, 60)
            local ctx = make_ctx({ uri = "/rl_log" })
            filter.on_access(ctx)
            assert.is_nil(ctx.action_result)
            -- The per-day counter proves record_hit ran on exceed: previously
            -- the counter was incremented but nothing was written.
            local daily = shared:get("waf_rule_stats:rl_log:today:" .. os.date("!%Y%m%d"))
            assert.is_not_nil(daily)
            assert.equals(1, tonumber(daily))
            cleanup({ "rl_log" }, { slot })
        end)
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
        local ctx2 = make_ctx({
            uri = "/any-path",
            remote_addr = ip,
        })
        filter.on_access(ctx2)
        -- No longer flagged, no rules match /any-path
        assert.is_nil(ctx2.action_result)
    end)

end)
