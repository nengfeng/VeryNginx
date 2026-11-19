-- -*- coding: utf-8 -*-
-- Config-save validation for named matcher definitions. A rule referencing a
-- matcher is checked at rule-save time, but the matcher itself can be edited
-- later; an invalid regex/IP would silently turn every referencing rule into a
-- dead rule.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

local function ensure_ngx()
    if not _G.ngx then _G.ngx = {} end
    local ngx = _G.ngx
    function ngx.log() end
    ngx.WARN = 6; ngx.ERR = 5
    ngx.time = function() return 1700000000 end
    ngx.now = function() return 1700000000 end
    ngx.md5 = function(s) return tostring(#s) end
    ngx.re = {
        compile = function(p)
            if p == "(" then return nil, "invalid" end
            return p
        end,
    }
    ngx.shared = setmetatable({}, {
        __index = function(_, name)
            ngx._stores = ngx._stores or {}
            if not ngx._stores[name] then ngx._stores[name] = {} end
            local st = ngx._stores[name]
            return {
                get = function(_, key) return st[key] end,
                set = function(_, key, val) st[key] = val; return true end,
                add = function(_, key, val)
                    if st[key] then return false end
                    st[key] = val; return true
                end,
                delete = function(_, key) st[key] = nil end,
                incr = function(_, key, delta, init)
                    st[key] = (st[key] or init or 0) + delta
                    return st[key]
                end,
                expire = function() end,
            }
        end,
    })
end
ensure_ngx()

local config = require "core.config"

local function cfg(matcher)
    return {
        version = "2.0",
        admin = {},
        matcher = matcher or {},
        rule = {},
    }
end

describe("config named matcher validation", function()

    it("accepts valid regex and IP matchers", function()
        local ok, err = config.validate_config(cfg({
            safe = { URI = { operator = "≈", value = "^/admin" } },
            ip = { IP = { operator = "=", value = "203.0.113.1" } },
        }))
        assert.is_true(ok, tostring(err))
    end)

    it("rejects an invalid regex", function()
        local ok, err = config.validate_config(cfg({
            bad = { URI = { operator = "≈", value = "(" } },
        }))
        assert.is_false(ok)
        assert.is_truthy(tostring(err):find("invalid regex", 1, true))
    end)

    it("rejects an invalid IP value", function()
        local ok, err = config.validate_config(cfg({
            bad = { IP = { operator = "=", value = "999.1.1.1" } },
        }))
        assert.is_false(ok)
        assert.is_truthy(tostring(err):find("IP", 1, true))
    end)

    it("rejects CIDR in an IP matcher", function()
        local ok, err = config.validate_config(cfg({
            bad = { IP = { operator = "=", value = "10.0.0.0/8" } },
        }))
        assert.is_false(ok)
        assert.is_truthy(tostring(err):find("CIDR", 1, true))
    end)

    it("rejects an unknown Composite operator", function()
        local ok, err = config.validate_config(cfg({
            bad = { Composite = { operator = "XOR", conditions = {
                { URI = { operator = "=", value = "/x" } },
            } } },
        }))
        assert.is_false(ok)
        assert.is_truthy(tostring(err):find("AND/OR/NOT", 1, true))
    end)

end)
