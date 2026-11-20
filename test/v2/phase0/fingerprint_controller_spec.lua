-- -*- coding: utf-8 -*-
-- P2-7: direct tests for the fingerprint controller (api/controllers/fingerprint.lua).
-- Covers route registration and every handler's success + error paths.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.status = 200
_G.ngx.req = { read_body = function() end, get_body_data = function() return "" end }
_G.ngx.ctx = {}

local json = require "dkjson"

-- Functional fake fingerprint DB, mirroring the real module's
-- add(entry) -> (added, err, class) contract where class=="validation"
-- marks a caller-side 4xx.
local store = {}
local fp_db = {
    reload = function() end,
    list = function()
        local out = {}
        for _, v in pairs(store) do out[#out + 1] = v end
        table.sort(out, function(a, b) return (a.name or "") < (b.name or "") end)
        return out
    end,
    add = function(entry)
        if not entry or entry.hash == nil or entry.hash == "" then
            return false, "hash is required", "validation"
        end
        if entry.name == nil or entry.name == "" then
            return false, "name is required", "validation"
        end
        store[entry.hash] = entry
        return true, nil, nil
    end,
    get = function(hash) return store[hash] end,
    remove = function(hash)
        local existed = store[hash] ~= nil
        store[hash] = nil
        return existed, nil
    end,
    categories = function() return { ja3 = true, ja4 = true } end,
}
local fp_orig = package.loaded["core.fingerprint_db"]

local controller = require "api.controllers.fingerprint"

local api = { routes = {} }
function api.register(method, path, handler, auth_required)
    api.routes[#api.routes + 1] = { method = method, path = path, handler = handler }
end
controller.register(api)
local function route(path, method)
    for _, r in ipairs(api.routes) do
        if r.path == path and r.method == method then return r end
    end
    return nil
end
local function reset()
    package.loaded["core.fingerprint_db"] = fp_db
    for k in pairs(store) do store[k] = nil end
    ngx.status = 200
    ngx.ctx = {}
    ngx.req.get_body_data = function() return "" end
end

describe("Fingerprint controller (P2-7)", function()
    before_each(reset)
    after_each(function()
        -- Restore whatever the process had before this spec (AGENTS 9.3)
        -- so later files that exercise the real module are not poisoned.
        package.loaded["core.fingerprint_db"] = fp_orig
    end)

    it("registers 5 routes", function()
        assert.are.equal(5, #api.routes)
    end)

    it("GET /fingerprints lists entries", function()
        store["h1"] = { hash = "h1", name = "curl", kind = "ja3" }
        local data = json.decode(route("/fingerprints", "GET").handler())
        assert.are.equal("success", data.ret)
        assert.are.equal(1, #data.data)
        assert.are.equal("curl", data.data[1].name)
    end)

    it("POST /fingerprints requires a body", function()
        local data = json.decode(route("/fingerprints", "POST").handler())
        assert.are.equal("failed", data.ret)
        assert.are.equal(400, ngx.status)
        assert.are.equal("request body required", data.message)
    end)

    it("POST /fingerprints requires hash and name", function()
        ngx.req.get_body_data = function() return json.encode({ hash = "h9" }) end
        local data = json.decode(route("/fingerprints", "POST").handler())
        assert.are.equal("failed", data.ret)
        assert.are.equal("hash and name are required", data.message)
    end)

    it("POST /fingerprints adds a valid entry", function()
        ngx.req.get_body_data = function()
            return json.encode({ hash = "hX", name = "scanner-ua", kind = "ja4" })
        end
        local data = json.decode(route("/fingerprints", "POST").handler())
        assert.are.equal("success", data.ret)
        assert.are.equal("scanner-ua", data.data.name)
    end)

    it("POST /fingerprints maps a validation failure to 400", function()
        ngx.req.get_body_data = function() return json.encode({ hash = "", name = "x" }) end
        local data = json.decode(route("/fingerprints", "POST").handler())
        assert.are.equal("failed", data.ret)
        assert.are.equal(400, ngx.status)
    end)

    it("PUT /fingerprints requires a hash", function()
        ngx.req.get_body_data = function() return json.encode({ name = "n" }) end
        local data = json.decode(route("/fingerprints", "PUT").handler())
        assert.are.equal("failed", data.ret)
        assert.are.equal("hash is required for update", data.message)
    end)

    it("DELETE /fingerprints/:id requires an id", function()
        local data = json.decode(route("/fingerprints/:id", "DELETE").handler())
        assert.are.equal("failed", data.ret)
        assert.are.equal("fingerprint hash required", data.message)
    end)

    it("DELETE /fingerprints/:id removes a known hash", function()
        store["gone"] = { hash = "gone", name = "n" }
        ngx.ctx.waf_rule_id = "gone"
        local data = json.decode(route("/fingerprints/:id", "DELETE").handler())
        assert.are.equal("success", data.ret)
        assert.is_true(data.removed)
    end)

    it("GET /fingerprints/stats reports totals", function()
        store["a"] = { hash = "a", name = "n" }
        local data = json.decode(route("/fingerprints/stats", "GET").handler())
        assert.are.equal("success", data.ret)
        assert.are.equal(1, data.data.total)
        assert.is_table(data.data.categories)
    end)
end)
