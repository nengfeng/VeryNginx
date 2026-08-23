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

    it("denies public hostname when DNS unavailable (fail-closed)", function()
        -- No DNS resolver in the test harness -> fail-closed denies public host.
        local ok, err = check("https://example.com/hook")
        assert.is_false(ok, "public hostname must be denied when DNS unavailable")
        assert.truthy(err and err:find("DNS resolution unavailable"), "error must mention DNS unavailability, got: " .. tostring(err))
    end)
end)

-- Config-level save-time validation must reject the same URLs. This block
-- guards against drift: config.validate_config delegates to
-- alerting.validate_webhook_url, so link-local and ::ffff: mapped IPv6 must be
-- rejected at save time too (previously the inlined config check missed them).
describe("config webhook SSRF validation at save time", function()

    local json = require "dkjson"

    -- Build a minimal valid config carrying the webhook URL under test.
    local function cfg_with(url)
        return {
            version = "2.0",
            matcher = {},
            matcher_id = {},
            rule = { frequency_limit = {} },
            frequency = { per_ip = { enabled = false } },
            summary = { enable = false },
            cc = { enabled = false },
            ipv4 = { enabled = true },
            ipv6 = { enabled = false, prefix_aggregation = false },
            kb_ip_blocking = {},
            kernel_ip_blocking = { enabled = false },
            vn_config = {},
            statistics = { enable = false },
            enable_summary = false,
            protected_prefix = {},
            protect_enable = false,
            enable = true,
            replace_monitor_ip = false,
            replace_ip = false,
            allow_ip = {},
            allow_domain = {},
            replace_url = {},
            cookie = { secret = "x" },
            admin = {},
            security = { session_secret = "x-secret-value-0123456789" },
            browser_verify = { enable = false },
            waf = { enable = false, rules = {} },
            cc_rules = {},
            debug = false,
            secret = "x",
            auto_ip_block_enable = false,
            ip_black_list = {},
            browser_verify_enable = false,
            ip_white_list = {},
            data_uuid = "x",
            cookie_secure = false,
            cookie_httponly = false,
            replace_post_args = {},
            alerting = { enabled = true, webhook_url = url },
            proxy_pass = {},
            ssi = { enable = false },
            set_cookie = {},
            inject_js = {},
            request_filter = { enable = false, rules = {} },
            response_filter = { enable = false, rules = {} },
            body = {},
            frequency_limit = { enable = false, rules = {} },
            data_filter = { enable = false, rules = {} },
        }
    end

    local function save(url)
        local config = require "core.config"
        local cfg = cfg_with(url)
        local n = 0
        for _ in pairs(cfg) do n = n + 1 end
        -- count fields so we know the table is well-formed; not used otherwise
        return config.validate_config(cfg)
    end

    it("blocks IPv6 loopback [::1] at save time", function()
        local ok, err = save("https://[::1]/hook")
        assert.is_false(ok, "[::1] must be rejected at save time")
        assert.truthy(err and err:find("webhook"), "error must mention webhook, got: " .. tostring(err))
    end)

    it("blocks IPv6 link-local [fe80::1] at save time (drift guard)", function()
        local ok, err = save("https://[fe80::1]/hook")
        assert.is_false(ok, "[fe80::1] must be rejected at save time")
    end)

    it("blocks IPv6 ::ffff: mapped [::ffff:10.0.0.1] at save time (drift guard)", function()
        local ok, err = save("https://[::ffff:10.0.0.1]/hook")
        assert.is_false(ok, "[::ffff:10.0.0.1] must be rejected at save time")
    end)

    it("denies public hostname at save time when DNS unavailable", function()
        local ok, err = save("https://example.com/hook")
        assert.is_false(ok, "public hostname must be denied at save time when DNS unavailable")
        assert.truthy(err and err:find("DNS resolution unavailable"), "error must mention DNS unavailability, got: " .. tostring(err))
    end)
end)
