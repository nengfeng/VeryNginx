-- -*- coding: utf-8 -*-
-- Tests for POST /frequency/templates/:id (handle_template_apply).
-- M3-freq: template apply must validate IP matcher values (via
-- validate_rule_ip_matchers), so a matcherJson override carrying a malformed
-- IP (e.g. "999.1.1.1") is rejected instead of silently creating a rule that
-- never matches.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.sleep = function() end
_G.ngx.status = 200
_G.ngx.header = { content_type = "application/json; charset=utf-8" }
_G.ngx.var = { uri = "/verynginx/frequency/templates/login_bruteforce" }

_G.ngx.shared = setmetatable({_cache = {}}, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v) st[k] = v; return true, nil end,
                add = function(_, k, v) if st[k] then return false, "exists" end
                    st[k] = v; return true, nil end,
                incr = function(_, k, d, i)
                    if st[k] == nil then st[k] = (i or 0) end
                    st[k] = st[k] + d; return st[k], nil end,
                delete = function(_, k) st[k] = nil end,
                expire = function() end,
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
            }
        end
        return t._cache[name]
    end,
})

-- Mock config so save() succeeds and rule storage is isolated.
local mock_config = {
    rule = { frequency_limit = {} },
    ip_reputation = {},
    kernel_ip_blocking = { enabled = false },
}
local config_module = {
    load_from_file = function() end,
    report = function() return "{}" end,
    save = function(cfg) return true, nil end,
    atomic_mutate = function(fn)
        local c = mock_config
        fn(c)
        return true, nil
    end,
}
setmetatable(config_module, {
    __index = function(t, k) return mock_config[k] end,
})
package.loaded["core.config"] = config_module

package.loaded["core.ip_reputation"] = {
    is_whitelisted = function() return false end,
}

-- Build the API and register only the frequency controller.
local api = require("api.init")
local frequency = require("api.controllers.frequency")
frequency.register(api)

local function find_route(method, path)
    for _, r in ipairs(api.routes) do
        if r.path == path and r.method == method then return r end
    end
    return nil
end

describe("POST /frequency/templates/:id IP matcher validation", function()
    local dkjson = require "dkjson"

    before_each(function()
        _G.ngx.req = {
            read_body = function() end,
            get_body_data = function() return nil end,
            get_method = function() return "POST" end,
        }
        _G.ngx.ctx = {}
        _G.ngx.status = 200
        mock_config.rule = { frequency_limit = {} }
    end)

    local function post_template(id, overrides)
        _G.ngx.var.uri = "/verynginx/frequency/templates/" .. id
        _G.ngx.ctx.waf_rule_id = id
        _G.ngx.req.get_body_data = function()
            if overrides then return dkjson.encode(overrides) end
            return nil
        end
        local route = find_route("POST", "/frequency/templates/:id")
        assert.is_truthy(route, "template apply route registered")
        return dkjson.decode(route.handler())
    end

    it("rejects matcherJson with malformed IP 999.1.1.1", function()
        local data = post_template("login_bruteforce", {
            matcherJson = dkjson.encode({ IP = { operator = "=", value = "999.1.1.1" } }),
        })
        assert.are.equal("failed", data.ret,
            "template apply with bad IP matcher must be rejected")
        assert.truthy(data.message and data.message:find("invalid IP"),
            "error must mention invalid IP, got: " .. tostring(data.message))
    end)

    it("rejects matcherJson with out-of-range octet", function()
        local data = post_template("api_abuse", {
            matcherJson = dkjson.encode({ IP = { operator = "=", value = "1.2.3.999" } }),
        })
        assert.are.equal("failed", data.ret)
    end)

    it("accepts template apply with valid URI matcher (no IP)", function()
        local data = post_template("login_bruteforce", {
            matcherJson = dkjson.encode({ URI = { operator = "≈", value = "/login" } }),
        })
        assert.are.equal("success", data.ret,
            "valid template apply must succeed, got: " .. tostring(data.message))
    end)

    it("accepts template apply with no overrides", function()
        local data = post_template("login_bruteforce", nil)
        assert.are.equal("success", data.ret)
    end)

    it("rejects matcherJson IP with CIDR notation (matcher has no CIDR support)", function()
        local data = post_template("crawler", {
            matcherJson = dkjson.encode({ IP = { operator = "=", value = "10.0.0.0/8" } }),
        })
        assert.are.equal("failed", data.ret,
            "CIDR in IP matcher must be rejected (matcher can only do equality/regex)")
        assert.truthy(data.message and data.message:find("CIDR"),
            "error must mention CIDR, got: " .. tostring(data.message))
    end)

    it("accepts matcherJson IP that is a plain valid address", function()
        local data = post_template("crawler", {
            matcherJson = dkjson.encode({ IP = { operator = "=", value = "10.0.0.1" } }),
        })
        assert.are.equal("success", data.ret,
            "plain valid IP matcher must be accepted, got: " .. tostring(data.message))
    end)
end)
