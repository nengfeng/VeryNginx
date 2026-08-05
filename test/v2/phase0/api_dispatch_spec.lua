-- -*- coding: utf-8 -*-
-- Dispatch-level tests for api.init middleware + waf_rules controller.
-- Covers:
--   * rate-limit key derivation uses the route pattern (:id), not the concrete URI
--   * confirm endpoint validates the proposed rule change before applying

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end

local captured_keys = {}
local captured_action = nil

_G.ngx.log = function() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.sleep = function() end
_G.ngx.md5 = function(s) return s end
_G.ngx.status = 200
_G.ngx.header = { content_type = "application/json; charset=utf-8" }
_G.ngx.ctx = {}
_G.ngx.var = { uri = "/verynginx/waf/rules", remote_addr = "127.0.0.1" }
_G.ngx.req = {
    get_method = function() return _G.ngx._method or "GET" end,
    get_headers = function() return {} end,
    get_uri_args = function() return {} end,
    read_body = function() end,
    get_body_data = function() return "{}" end,
}

local function make_dict()
    local st = {}
    return {
        get = function(_, k) return st[k] end,
        set = function(_, k, v) st[k] = v; return true, nil end,
        add = function(_, k, v) if st[k] then return false, "exists" end; st[k] = v; return true, nil end,
        incr = function(_, k, d, i) if st[k] == nil then st[k] = (i or 0) end; st[k] = st[k] + d; return st[k], nil end,
        delete = function(_, k) st[k] = nil end,
        flush_all = function() for k in pairs(st) do st[k] = nil end end,
    }
end

local dicts = {}
_G.ngx.shared = setmetatable({}, {
    __index = function(_, name)
        if not dicts[name] then dicts[name] = make_dict() end
        return dicts[name]
    end,
})

-- ---------------------------------------------------------------------------
-- Stub dependencies. Installed via package.loaded (NOT package.preload) and
-- cleared immediately after `require "api.init"` completes: api.init and the
-- controllers capture these as module locals at load time, so clearing the
-- entries afterwards prevents the stubs from leaking into other spec files.
-- ---------------------------------------------------------------------------
package.loaded["core.config"] = {
    base_uri = "/verynginx",
    ip_reputation = {},
    waf = { enabled = true },
}

package.loaded["api.auth"] = (function()
    local m = {}
    function m.middleware() return true end
    return m
end)()

package.loaded["api.rate_limit"] = (function()
    local m = {}
    function m.allow(key, limit, window)
        captured_keys[#captured_keys + 1] = { key = key, limit = limit, window = window }
        return true
    end
    return m
end)()

package.loaded["core.audit"] = (function()
    local m = {}
    function m.log() end
    return m
end)()

package.loaded["api.helpers"] = (function()
    local m = {}
    function m.get_request_args() return {} end
    return m
end)()

local rules_store = {
    version = 1,
    rules = {
        {
            id = "rule_1", name = "r1", category = "sqli", severity = "high",
            action = "block", enable = true, matcher = { URI = { "foo" } },
        },
    },
}
local saved = nil

package.loaded["waf-rule-manager"] = (function()
    local m = {}
    function m.load_rules() return rules_store end
    function m.validate_rule(rule)
        if rule and rule.action == "evil_action" then
            return false, "invalid action"
        end
        return true
    end
    function m._save_rules_through_config(rules)
        saved = rules
        return true
    end
    function m.reload() return true end
    return m
end)()

-- Stub out every controller except waf_rules (the one under test).
for _, name in ipairs({ "auth", "config", "waf_stats", "waf_recommender",
                         "reputation", "geoip", "fingerprint", "frequency",
                         "plugins", "kernel_blocking" }) do
    package.loaded["api.controllers." .. name] = {
        register = function() end,
    }
end

local json = require "dkjson"
local api = require "api.init"

-- api.init captured all stub references at load; drop them so they cannot leak
-- into later spec files in the same busted process.
package.loaded["core.config"] = nil
package.loaded["api.auth"] = nil
package.loaded["api.rate_limit"] = nil
package.loaded["core.audit"] = nil
package.loaded["api.helpers"] = nil
package.loaded["waf-rule-manager"] = nil
for _, name in ipairs({ "auth", "config", "waf_stats", "waf_recommender",
                         "reputation", "geoip", "fingerprint", "frequency",
                         "plugins", "kernel_blocking" }) do
    package.loaded["api.controllers." .. name] = nil
end

local function run_dispatch(uri, method)
    captured_action = nil
    _G.ngx._method = method
    _G.ngx.ctx = {}
    _G.ngx.status = 200
    local ctx = {
        request = { uri = uri },
        set_action = function(_, _, a) captured_action = a end,
        get_data = function() return "tester" end,
    }
    api.dispatch(ctx)
    return ctx, captured_action
end

describe("api rate-limit key derivation", function()
    before_each(function()
        captured_keys = {}
    end)

    it("uses the route pattern for parameterized routes, not the concrete URI", function()
        -- GET /waf/rules/123 must be bucketed as /waf/rules/:id so varying
        -- the id cannot mint a fresh bucket per request.
        run_dispatch("/verynginx/waf/rules/123", "GET")
        assert.are.equal(1, #captured_keys)
        assert.are.equal("api:GET:/waf/rules/:id:tester", captured_keys[1].key)
        assert.are.equal(60, captured_keys[1].limit)
        assert.are.equal(60, captured_keys[1].window)
    end)
end)

describe("waf rule confirm endpoint", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_session:flush_all()
        saved = nil
        rules_store.rules = {
            {
                id = "rule_1", name = "r1", category = "sqli", severity = "high",
                action = "block", enable = true, matcher = { URI = { "foo" } },
            },
        }
    end)

    it("rejects an invalid proposed change with 400 and does not save", function()
        ngx.shared.vn_config:set("waf_pending_rule:rule_1", json.encode({
            rule_id = "rule_1", staged_at = 1,
            proposed = { action = "evil_action", severity = "critical" },
        }))
        local _, act = run_dispatch("/verynginx/waf/rules/rule_1/confirm", "POST")
        assert.are.equal(400, _G.ngx.status)
        assert.are.equal(400, act.response.code)
        local body = json.decode(act.response.body)
        assert.are.same("failed", body.ret)
        assert.matches("invalid proposed change", body.message)
        assert.is_nil(saved, "save_rules must not be called for an invalid proposal")
        -- Pending record is preserved on rejection
        assert.is_truthy(ngx.shared.vn_config:get("waf_pending_rule:rule_1"))
    end)

    it("applies a valid proposed change through the save path", function()
        ngx.shared.vn_config:set("waf_pending_rule:rule_1", json.encode({
            rule_id = "rule_1", staged_at = 1,
            proposed = { action = "block", severity = "critical" },
        }))
        run_dispatch("/verynginx/waf/rules/rule_1/confirm", "POST")
        assert.are.equal(200, _G.ngx.status)
        assert.is_truthy(saved, "save must be called for a valid proposal")
        assert.are.equal("critical", saved[1].severity)
        assert.is_nil(ngx.shared.vn_config:get("waf_pending_rule:rule_1"),
            "pending record cleared after successful confirm")
    end)
end)
