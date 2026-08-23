-- -*- coding: utf-8 -*-
-- Direct coverage for AGENTS.md §10.14: EMPTY/SHORT session_secret must be
-- fail-closed in api/auth.lua. HMAC("", payload) is forgeable offline — the
-- old `if not secret` guard passed "" because empty string is truthy in Lua,
-- letting an attacker mint admin sessions. These tests pin BOTH defense
-- points (verify-side strategy.check and login-side token issuance) against
-- nil / "" / short secrets, including a forged token signed with "" itself.
--
-- CI runs busted without --lpath; every spec prepends its own paths.
package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;verynginx/lua_script/module/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5
_G.ngx.time = _G.ngx.time or function() return 1700000000 end

-- Minimal base64/md5 shims ONLY if the shared helper doesn't already provide
-- them (core.session signs/verifies tokens through these).
if not _G.ngx.md5 then
    _G.ngx.md5 = function(s) return tostring(#s) .. ":" .. s end -- fake, deterministic
end
local function b64(s)
    -- toy codec: reversible enough for round-trip within this process
    return "|" .. s
end
if not _G.ngx.encode_base64 then _G.ngx.encode_base64 = b64 end
if not _G.ngx.decode_base64 then
    _G.ngx.decode_base64 = function(s) return s:sub(2) end
end

describe("auth.lua 空 session_secret fail-closed (§10.14)", function()
    local fake_cfg, auth, session, saved_loaded

    local function fresh(secret_value, omit_security)
        fake_cfg = {
            cookie_prefix = "verynginx",
            admin = { { user = "admin", password_hash = "h", enable = true } },
            security = nil,
        }
        if not omit_security then
            fake_cfg.security = { session_secret = secret_value }
        end
        package.preload["core.config"] = function() return fake_cfg end
        package.loaded["core.config"] = nil
        -- Isolate collaborators: cookie delivers our token; rate limit always
        -- allows; password verify always passes (secret guard is the SUT).
        package.loaded["cookie"] = {
            new = function()
                return { get_all = function() return { verynginx_session = rawget(_G, "__tok") } end }
            end,
        }
        package.loaded["api.rate_limit"] = { allow = function() return true end }
        package.loaded["core.password_hash"] = { verify = function() return true end }
        package.loaded["api.csrf"] = { verify = function() return true end }
        package.loaded["api.auth"] = nil
        package.loaded["core.session"] = nil
        auth = require "api.auth"
        session = require "core.session"
        return auth.strategies["session"]
    end

    setup(function()
        saved_loaded = {
            cookie = package.loaded["cookie"],
            rl = package.loaded["api.rate_limit"],
            ph = package.loaded["core.password_hash"],
            csrf = package.loaded["api.csrf"],
            cfg_pre = package.preload["core.config"],
            cfg = package.loaded["core.config"],
            auth = package.loaded["api.auth"],
            sess = package.loaded["core.session"],
        }
    end)

    after_each(function()
        -- process-global hygiene (AGENTS.md §9.3 trap)
        package.loaded["cookie"] = saved_loaded.cookie
        package.loaded["api.rate_limit"] = saved_loaded.rl
        package.loaded["core.password_hash"] = saved_loaded.ph
        package.loaded["api.csrf"] = saved_loaded.csrf
        package.preload["core.config"] = saved_loaded.cfg_pre
        package.loaded["core.config"] = saved_loaded.cfg
        package.loaded["api.auth"] = saved_loaded.auth
        package.loaded["core.session"] = saved_loaded.sess
    end)

    local ctx = function() return {} end

    it("verify 侧: 攻击者用空密钥伪造的合法签名 token 被拒绝", function()
        local strat = fresh("")
        local forged = session.sign({ user = "admin", expire_at = ngx.time() + 600 }, "")
        rawset(_G, "__tok", forged)
        assert.is_false(strat.check(ctx()))
    end)

    it("verify 侧: nil / 短(<16) / security 表缺失 全部拒绝", function()
        local strat15 = fresh(string.rep("x", 15))
        rawset(_G, "__tok", session.sign({ user = "admin", expire_at = ngx.time() + 600 }, string.rep("x", 15)))
        assert.is_false(strat15.check(ctx()))

        local strat_nil = fresh(nil)
        rawset(_G, "__tok", session.sign({ user = "admin", expire_at = ngx.time() + 600 }, ""))
        assert.is_false(strat_nil.check(ctx()))

        local strat_absent = fresh(nil, true) -- config.security 整表缺失
        rawset(_G, "__tok", session.sign({ user = "admin", expire_at = ngx.time() + 600 }, ""))
        assert.is_false(strat_absent.check(ctx()))
    end)

    it("verify 侧阳性对照: ≥16 合法密钥 + 正确签名 + admin 存在 ⇒ 通过", function()
        local good = "unit-test-secret-0123456789"
        local strat = fresh(good)
        rawset(_G, "__tok", session.sign({ user = "admin", expire_at = ngx.time() + 600 }, good))
        assert.is_true(strat.check(ctx()))
    end)

    it("login 侧: 凭证正确但密钥空/短 ⇒ 拒发 token 并返回明确错误", function()
        local strat_empty = fresh("")
        local ok, err = strat_empty.login("admin", "pw")
        assert.is_false(ok)
        assert.matches("session_secret missing or too short", tostring(err))

        local strat_short = fresh("short")
        ok, err = strat_short.login("admin", "pw")
        assert.is_false(ok)
        assert.matches("too short", tostring(err))

        local strat_absent = fresh(nil, true)
        ok, err = strat_absent.login("admin", "pw")
        assert.is_false(ok)
        assert.matches("too short", tostring(err))
    end)

    it("login 侧阳性对照: 合法密钥签发可被 verify 接受的 token", function()
        local good = "unit-test-secret-0123456789"
        local strat = fresh(good)
        local ok, token = strat.login("admin", "pw")
        assert.is_true(ok)
        rawset(_G, "__tok", token)
        assert.is_true(strat.check(ctx()))
    end)
end)
