-- -*- coding: utf-8 -*-
-- Tests for webhook URL SSRF validation (alerting.validate_webhook_url).
-- M3: IPv6 bracket literals like https://[::1]/hook must not bypass the
-- private-IP check. The host extractor used to mangle "[::1]" into "[".

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
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

-- Load alerting and use the exposed SSRF validator directly (avoids the
-- outbound HTTP request that send_webhook would make after validation passes).
local alerting = require "core.alerting"

-- reach into the module's local validate_webhook_url via send_webhook's
-- validation path: send_webhook calls validate_webhook_url first and returns
-- {false, err} on rejection. We test the public surface.
local function check(url)
    return alerting.validate_webhook_url(url)
end

describe("webhook SSRF validation", function()

    it("blocks IPv6 loopback bracket literal [::1]", function()
        local ok, err = check("https://[::1]/hook")
        assert.is_false(ok, "[::1] must be blocked as internal IP")
        assert.truthy(err:find("internal IP"), "expected internal IP rejection, got: " .. tostring(err))
    end)

    it("blocks IPv6 link-local [fe80::1]", function()
        local ok, err = check("https://[fe80::1]:8443/hook")
        assert.is_false(ok, "[fe80::1] must be blocked as internal IP")
    end)

    it("blocks IPv6 ULA [fc00::1]", function()
        local ok, err = check("https://[fc00::1]/hook")
        assert.is_false(ok, "[fc00::1] must be blocked as internal IP")
    end)

    it("blocks IPv6 ULA [fd00::1]", function()
        local ok, err = check("https://[fd00::1]/hook")
        assert.is_false(ok, "[fd00::1] must be blocked as internal IP")
    end)

    it("blocks IPv6 loopback with port [::1]:443", function()
        local ok, err = check("https://[::1]:443/hook")
        assert.is_false(ok, "[::1]:443 must be blocked as internal IP")
    end)

    it("allows public IPv6 literal [2001:db8::1]", function()
        local ok, err = check("https://[2001:db8::1]/hook")
        assert.is_true(ok, "public IPv6 must be allowed, got err: " .. tostring(err))
    end)

    it("blocks http (non-https)", function()
        local ok, err = check("http://example.com/hook")
        assert.is_false(ok, "http must be blocked")
    end)

    it("blocks IPv4 loopback 127.0.0.1", function()
        local ok, err = check("https://127.0.0.1/hook")
        assert.is_false(ok, "127.0.0.1 must be blocked")
    end)

    it("blocks private IPv4 10.x", function()
        local ok, err = check("https://10.0.0.1/hook")
        assert.is_false(ok, "10.0.0.1 must be blocked")
    end)

    it("allows public hostname (best-effort, no DNS in test)", function()
        -- No DNS resolver in the test harness -> best-effort allows public host.
        local ok, err = check("https://example.com/hook")
        assert.is_true(ok, "public hostname must be allowed, got err: " .. tostring(err))
    end)
end)
