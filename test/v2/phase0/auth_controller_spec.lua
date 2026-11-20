-- -*- coding: utf-8 -*-
-- P2-7: direct tests for the auth controller (login / logout / session).
-- The controller binds core.config, api.auth, api.helpers and core.audit at
-- require time, so all four are mocked before the controller loads; the
-- cookie / core.session modules are required lazily inside handle_logout.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.status = 200
_G.ngx.ctx = {}
_G.ngx.header = {}

local json = require "dkjson"

local login_args = {}
local cookie_fields = {}
local session_revoked = nil

local config_fake = { auth_strategy = nil, cookie_prefix = "verynginx" }

local auth_fake = {}
function auth_fake.set_session_cookie(token) auth_fake.cookie_set = token end
auth_fake.strategies = {
    session = {
        login = function(_user, password)
            if password == "right" then return true, "tok-123" end
            return false, "bad credentials"
        end,
    },
}

local helpers_fake = {}
function helpers_fake.get_request_args() return login_args end

local audit_fake = { events = {} }
function audit_fake.log(action, detail, user)
    audit_fake.events[#audit_fake.events + 1] = { action = action, detail = detail, user = user }
end

local cookie_fake = {}
function cookie_fake.new(_self)
    return { get_all = function() return cookie_fields end }
end

local session_fake = {}
function session_fake.revoke(token) session_revoked = token end

local KEYS = { "core.config", "api.auth", "api.helpers", "core.audit" }
local orig = {}
for _, k in ipairs(KEYS) do orig[k] = package.loaded[k] end
package.loaded["core.config"] = config_fake
package.loaded["api.auth"] = auth_fake
package.loaded["api.helpers"] = helpers_fake
package.loaded["core.audit"] = audit_fake

local controller = require "api.controllers.auth"
local api = { routes = {} }
function api.register(m, p, h, a) api.routes[#api.routes + 1] = { m = m, p = p, h = h, a = a } end
controller.register(api)
local function route(path, method)
    for _, r in ipairs(api.routes) do
        if r.p == path and r.m == method then return r end
    end
    return nil
end

describe("Auth controller (P2-7)", function()
    before_each(function()
        login_args = {}
        cookie_fields = {}
        session_revoked = nil
        auth_fake.cookie_set = nil
        audit_fake.events = {}
        config_fake.auth_strategy = nil
        package.loaded["cookie"] = cookie_fake
        package.loaded["core.session"] = session_fake
        ngx.status = 200
        ngx.ctx = {}
        ngx.header = {}
    end)
    after_each(function()
        for _, k in ipairs(KEYS) do package.loaded[k] = orig[k] end
        package.loaded["cookie"] = nil
        package.loaded["core.session"] = nil
    end)

    it("registers 3 routes with the right auth flags", function()
        assert.are.equal(3, #api.routes)
        assert.is_false(route("/login", "POST").a)
        assert.is_true(route("/logout", "POST").a)
        assert.is_true(route("/session", "GET").a)
    end)

    it("POST /login requires user and password", function()
        local data = json.decode(route("/login", "POST").h())
        assert.are.equal(400, ngx.status)
        assert.are.equal("user and password required", data.message)
    end)

    it("POST /login maps an unknown strategy to 500", function()
        config_fake.auth_strategy = "jwt"
        login_args = { user = "u", password = "right" }
        local data = json.decode(route("/login", "POST").h())
        assert.are.equal(500, ngx.status)
        assert.are.equal("auth strategy not available", data.message)
    end)

    it("POST /login success sets the session cookie and audits", function()
        login_args = { user = "u", password = "right" }
        local data = json.decode(route("/login", "POST").h())
        assert.are.equal(200, ngx.status)
        assert.are.equal("success", data.ret)
        assert.are.equal("tok-123", data.token)
        assert.are.equal("tok-123", auth_fake.cookie_set)
        assert.are.equal(1, #audit_fake.events)
        assert.are.equal("login_success", audit_fake.events[1].action)
    end)

    it("POST /login failure returns 401 and audits login_failed", function()
        login_args = { user = "u", password = "wrong" }
        local data = json.decode(route("/login", "POST").h())
        assert.are.equal(401, ngx.status)
        assert.are.equal("failed", data.ret)
        assert.are.equal("bad credentials", data.message)
        assert.are.equal("login_failed", audit_fake.events[1].action)
    end)

    it("POST /logout revokes the session token from the cookie", function()
        cookie_fields = { verynginx_session = "tok-999" }
        local data = json.decode(route("/logout", "POST").h())
        assert.are.equal("success", data.ret)
        assert.are.equal("tok-999", session_revoked)
        assert.equal("verynginx_session=; Path=/; Max-Age=0", ngx.header["Set-Cookie"])
    end)

    it("POST /logout clears the cookie even without a session token", function()
        cookie_fields = {}
        local data = json.decode(route("/logout", "POST").h())
        assert.are.equal("success", data.ret)
        assert.is_nil(session_revoked)
        assert.equal("verynginx_session=; Path=/; Max-Age=0", ngx.header["Set-Cookie"])
    end)

    it("GET /session without a ctx reports no active session", function()
        ngx.ctx.vn_ctx = nil
        local data = json.decode(route("/session", "GET").h())
        assert.are.equal(401, ngx.status)
        assert.are.equal("no active session", data.message)
    end)

    it("GET /session returns the authenticated user", function()
        ngx.ctx.vn_ctx = { get_data = function(_self, key)
            assert.are.equal("auth:user", key)
            return "alice"
        end }
        local data = json.decode(route("/session", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal("alice", data.user)
    end)
end)
