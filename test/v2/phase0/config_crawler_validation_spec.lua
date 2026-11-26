-- -*- coding: utf-8 -*-
-- Config-save validation for crawler exemption lists and crawler fetch
-- sources. The lists feed is_crawler_exempt(); a too-broad CIDR would exempt
-- a whole provider allocation, and the sources are fetched server-side, so a
-- private URL would be an SSRF launcher.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

local function ensure_ngx()
    if not _G.ngx then _G.ngx = {} end
    local ngx = _G.ngx
    function ngx.log() end
    ngx.WARN = 6; ngx.ERR = 5
    ngx.time = function() return 1700000000 end
    ngx.now = function() return 1700000000 end
    ngx.md5 = function(s) return tostring(#s) end
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

local function cfg(ip_rep)
    return {
        version = "2.0",
        admin = {},
        matcher = {},
        rule = {},
        ip_reputation = ip_rep or {},
    }
end

describe("config crawler list/source validation", function()

    it("accepts valid IPv4 ranges, bare verified addresses and https sources", function()
        local ok, err = config.validate_config(cfg({
            crawler_ip_whitelist = { "66.249.64.0/19", "203.0.113.1" },
            crawler_ip_verified = { "203.0.113.2", "2001:db8::1" },
            crawler_sources = {
                { key = "google", url = "https://203.0.113.10/google.json" },
            },
        }))
        assert.is_true(ok, tostring(err))
    end)

    it("rejects a too-broad crawler exemption range", function()
        local ok, err = config.validate_config(cfg({
            crawler_ip_whitelist = { "10.0.0.0/8" },
        }))
        assert.is_false(ok)
        assert.is_truthy(tostring(err):find("too broad", 1, true))
    end)

    it("rejects a CIDR in the verified-address list", function()
        local ok, err = config.validate_config(cfg({
            crawler_ip_verified = { "10.0.0.0/24" },
        }))
        assert.is_false(ok)
        assert.is_truthy(tostring(err):find("CIDR", 1, true))
    end)

    it("rejects IPv6 in the range list (cidr.match_any is IPv4-only)", function()
        local ok, err = config.validate_config(cfg({
            crawler_ip_whitelist = { "2001:db8::1" },
        }))
        assert.is_false(ok)
        assert.is_truthy(tostring(err):find("IPv6", 1, true))
    end)

    it("rejects a private crawler source URL", function()
        local ok, err = config.validate_config(cfg({
            crawler_sources = {
                { key = "google", url = "https://10.0.0.1/google.json" },
            },
        }))
        assert.is_false(ok)
        assert.is_truthy(tostring(err):find("internal IP", 1, true))
    end)

    it("rejects a non-https crawler source URL", function()
        local ok, err = config.validate_config(cfg({
            crawler_sources = {
                { key = "google", url = "http://203.0.113.11/google.json" },
            },
        }))
        assert.is_false(ok)
        assert.is_truthy(tostring(err):find("https", 1, true))
    end)

    it("accepts an absolute crawler_import_dir under the install root", function()
        local ok, err = config.validate_config(cfg({
            crawler_import_dir = os.getenv("PWD") .. "/verynginx/configs/crawler-import",
        }))
        assert.is_true(ok, tostring(err))
    end)

    it("rejects a crawler_import_dir outside the install root or with '..'", function()
        local ok1 = config.validate_config(cfg({ crawler_import_dir = "/etc" }))
        assert.is_false(ok1)
        local ok2 = config.validate_config(cfg({ crawler_import_dir = "/opt/verynginx/../etc" }))
        assert.is_false(ok2)
        local ok3 = config.validate_config(cfg({ crawler_import_dir = "relative/path" }))
        assert.is_false(ok3)
    end)

end)
