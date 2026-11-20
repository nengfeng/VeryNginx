-- -*- coding: utf-8 -*-
-- P2-7: direct tests for the waf_rules controller (CRUD + staging flow).
-- waf-rule-manager, core.audit and api.helpers are bound at require time;
-- core.random is required lazily by the pending-index spin lock. The shared
-- dicts carry the pending-rule slots, the pending index and rule stats.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.sleep = function(_) end
_G.ngx.status = 200
_G.ngx.ctx = {}
_G.ngx.var = {}
_G.ngx.req = {
    read_body = function() end,
    get_body_data = function() return "" end,
}
_G.ngx.shared = setmetatable({ _cache = {} }, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v) st[k] = v; return true, nil end,
                add = function(_, k, v) if st[k] then return false, "exists" end; st[k] = v; return true, nil end,
                incr = function(_, k, d, i) if st[k] == nil then st[k] = (i or 0) end; st[k] = st[k] + d; return st[k], nil end,
                delete = function(_, k) st[k] = nil end,
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
                get_keys = function(_d, _n)
                    local out = {}
                    for k in pairs(st) do out[#out + 1] = k end
                    table.sort(out)
                    return out
                end,
            }
        end
        return t._cache[name]
    end,
})

local json = require "dkjson"
local NOW = 1700000000

local wm = {
    _rules = {},
    _create_ok = true, _create_result = { id = "r9", name = "new", created_at = NOW, version = 1 },
    _create_err = "duplicate rule",
    _history = {},
    _drift_report = { drift = 1 }, _drift_err = "drift failed",
    _reload_ok = true, _reload_err = "reload failed",
    _rollback_ok = true, _rollback_err = "no such version",
    _update_ok = true, _update_result = { version = 7 }, _update_err = "update failed",
    _update_calls = {},
    _delete_ok = true, _delete_err = "not found",
    _validate_ok = true, _validate_err = "invalid rule",
    _save_ok = true, _save_err = "persist failed",
    _restore_result = { restored = 2, updated = 0 }, _restore_err = "factory file missing",
    _accept_result = { accepted = { "r1" }, skipped = { "r9" } }, _accept_err = "no ids",
}
function wm.load_rules() return { rules = wm._rules } end
function wm.create_rule(rule)
    if wm._create_ok then
        return true, wm._create_result or { id = rule.id, name = rule.name, created_at = NOW, version = 1 }
    end
    return false, wm._create_err
end
function wm.get_history(_limit) return wm._history end
function wm.factory_drift()
    if wm._drift_report ~= nil then return wm._drift_report end
    return nil, wm._drift_err
end
function wm.reload() return wm._reload_ok, wm._reload_err end
function wm.rollback(_rid, _version)
    if wm._rollback_ok then return true end
    return false, wm._rollback_err
end
function wm.update_rule(id, updates)
    wm._update_calls[#wm._update_calls + 1] = { id = id, updates = updates }
    if wm._update_ok then return true, wm._update_result end
    return false, wm._update_err
end
function wm.delete_rule(_id)
    if wm._delete_ok then return true end
    return false, wm._delete_err
end
function wm.validate_rule(_candidate) return wm._validate_ok, wm._validate_err end
function wm._save_rules_through_config(_rules) return wm._save_ok, wm._save_err end
function wm.restore_defaults(_opts)
    if wm._restore_result ~= nil then return wm._restore_result end
    return nil, wm._restore_err
end
function wm.accept_factory_actions(_ids)
    if wm._accept_result ~= nil then return wm._accept_result end
    return nil, wm._accept_err
end

local audit_fake = { events = {} }
function audit_fake.log(action, detail, _user)
    audit_fake.events[#audit_fake.events + 1] = { action = action, detail = detail }
end

local req_args = {}
local uri_args = {}
local helpers_fake = {}
function helpers_fake.get_request_args() return req_args end
local get_uri_args = function() return uri_args end

local random_fake = {}
function random_fake.bytes(_n) return "locktok" end

local KEYS = { "waf-rule-manager", "core.audit", "api.helpers" }
local orig = {}
for _, k in ipairs(KEYS) do orig[k] = package.loaded[k] end
package.loaded["waf-rule-manager"] = wm
package.loaded["core.audit"] = audit_fake
package.loaded["api.helpers"] = helpers_fake
_G.ngx.req.get_uri_args = get_uri_args

local controller = require "api.controllers.waf_rules"
local api = { routes = {} }
function api.register(m, p, h, a) api.routes[#api.routes + 1] = { m = m, p = p, h = h } end
controller.register(api)
local function route(path, method)
    for _, r in ipairs(api.routes) do
        if r.p == path and r.m == method then return r end
    end
    return nil
end
local function cfg() return ngx.shared.vn_config end
local PENDING = "waf_pending_rule:"

describe("WAF rules controller (P2-7)", function()
    before_each(function()
        ngx.shared.vn_config:flush_all()
        ngx.shared.vn_locks:flush_all()
        package.loaded["core.random"] = random_fake
        wm._rules = {
            { id = "r1", name = "SQLi", category = "sqli", severity = "critical", enable = true, priority = 10 },
            { id = "r2", name = "XSS", category = "xss", severity = "medium", enable = true, priority = 20 },
            { id = "r3", name = "Old sqli", category = "sqli", severity = "low", enable = false },
        }
        wm._create_ok = true; wm._history = {}
        wm._drift_report = { drift = 1 }
        wm._reload_ok = true; wm._rollback_ok = true
        wm._update_ok = true; wm._delete_ok = true
        wm._validate_ok = true; wm._save_ok = true
        wm._restore_result = { restored = 2, updated = 0 }
        wm._accept_result = { accepted = { "r1" }, skipped = { "r9" } }
        wm._update_calls = {}
        audit_fake.events = {}
        req_args = {}
        uri_args = {}
        ngx.status = 200
        ngx.ctx = {}
        ngx.req.get_body_data = function() return "" end
    end)
    after_each(function()
        package.loaded["core.random"] = nil
        for _, k in ipairs(KEYS) do package.loaded[k] = orig[k] end
    end)

    it("registers 17 routes", function()
        assert.are.equal(17, #api.routes)
    end)

    it("GET /waf/rules lists, filters and paginates with live stats", function()
        cfg():set("waf_rule_stats:r1", json.encode({ hit_count = 5, last_triggered = NOW - 10 }))
        local data = json.decode(route("/waf/rules", "GET").h())
        assert.are.equal(3, #data.data.rules)
        assert.are.equal(5, data.data.rules[1].hit_count)
        assert.are.equal(2, data.data.categories.sqli)
        assert.are.equal(1, data.data.pagination.total_pages)
        uri_args = { category = "sqli" }
        local filtered = json.decode(route("/waf/rules", "GET").h())
        assert.are.equal(2, filtered.data.pagination.total)
        uri_args = { severity = "medium" }
        assert.are.equal(1, #json.decode(route("/waf/rules", "GET").h()).data.rules)
        uri_args = { page = "99", limit = "2" }
        local paged = json.decode(route("/waf/rules", "GET").h())
        assert.are.equal(2, paged.data.pagination.page) -- clamped to total_pages
        assert.are.equal(1, #paged.data.rules)
    end)

    it("POST /waf/rules validates and creates", function()
        local h = route("/waf/rules", "POST").h
        local d1 = json.decode(h())
        assert.are.equal(400, ngx.status)
        assert.are.equal("request body required", d1.message)
        ngx.req.get_body_data = function() return "{{bad" end
        assert.are.equal("invalid JSON", json.decode(h()).message)
        wm._create_ok = false
        ngx.req.get_body_data = function() return json.encode({ id = "r9" }) end
        assert.are.equal("duplicate rule", json.decode(h()).message)
        wm._create_ok = true
        local ok = json.decode(h())
        assert.are.equal("success", ok.ret)
        assert.are.equal("r9", ok.data.id)
        assert.are.equal("waf_rule_created", audit_fake.events[1].action)
    end)

    it("GET /waf/rules/history slims entries to list-view fields", function()
        wm._history = {
            { version = 3, timestamp = NOW, action = "update", rule_count = 20, rule_data = "big" },
            { version = 2, timestamp = NOW - 86400, action = "create", rule_count = 19 },
        }
        local data = json.decode(route("/waf/rules/history", "GET").h())
        assert.are.equal(2, #data.data)
        assert.are.equal(3, data.data[1].version)
        assert.is_nil(data.data[1].rule_data)
    end)

    it("GET /waf/rules/factory-drift reports or 500s", function()
        local data = json.decode(route("/waf/rules/factory-drift", "GET").h())
        assert.are.equal("success", data.ret)
        assert.are.equal(1, data.data.drift)
        wm._drift_report = nil
        data = json.decode(route("/waf/rules/factory-drift", "GET").h())
        assert.are.equal(500, ngx.status)
        assert.are.equal("drift failed", data.message)
    end)

    it("POST /waf/rules/reload and /waf/rules/rollback", function()
        local data = json.decode(route("/waf/rules/reload", "POST").h())
        assert.are.equal("success", data.ret)
        assert.are.equal("waf_rules_reloaded", audit_fake.events[1].action)
        wm._reload_ok = false
        ngx.status = 200
        data = json.decode(route("/waf/rules/reload", "POST").h())
        assert.are.equal(400, ngx.status)
        assert.are.equal("reload failed", data.message)

        local rb = route("/waf/rules/rollback", "POST").h
        ngx.status = 200
        assert.are.equal("request body required", json.decode(rb()).message)
        ngx.req.get_body_data = function() return json.encode({}) end
        assert.are.equal("version is required", json.decode(rb()).message)
        ngx.req.get_body_data = function() return json.encode({ version = 3, rule_id = "r1" }) end
        assert.are.equal("success", json.decode(rb()).ret)
        wm._rollback_ok = false
        ngx.status = 200
        assert.are.equal("no such version", json.decode(rb()).message)
    end)

    it("GET/PUT/DELETE /waf/rules/:id", function()
        local get = route("/waf/rules/:id", "GET")
        ngx.ctx.waf_rule_id = nil
        ngx.status = 200
        assert.are.equal("rule id required", json.decode(get.h()).message)
        ngx.ctx.waf_rule_id = "rX"
        ngx.status = 200
        assert.are.equal(404, (function() local d = json.decode(get.h()) return ngx.status end)())
        ngx.ctx.waf_rule_id = "r1"
        ngx.status = 200
        local found = json.decode(get.h())
        assert.are.equal("SQLi", found.data.name)

        local del = route("/waf/rules/:id", "DELETE")
        ngx.ctx.waf_rule_id = nil
        ngx.status = 200
        assert.are.equal("rule id required", json.decode(del.h()).message)
        ngx.ctx.waf_rule_id = "r1"
        wm._delete_ok = false
        ngx.status = 200
        assert.are.equal(400, (function() json.decode(del.h()) return ngx.status end)())
        wm._delete_ok = true
        ngx.status = 200
        assert.are.equal("rule deleted", json.decode(del.h()).message)

        local put = route("/waf/rules/:id", "PUT")
        ngx.ctx.waf_rule_id = "r1"
        ngx.status = 200
        assert.are.equal("request body required", json.decode(put.h()).message)
        ngx.req.get_body_data = function() return json.encode({ priority = 99 }) end
        ngx.status = 200
        assert.are.equal("success", json.decode(put.h()).ret)
        assert.are.equal(7, wm._update_result.version)
    end)

    it("POST enable/disable route to update_rule with the right flag", function()
        ngx.ctx.waf_rule_id = "r1"
        json.decode(route("/waf/rules/:id/enable", "POST").h())
        json.decode(route("/waf/rules/:id/disable", "POST").h())
        assert.are.equal(2, #wm._update_calls)
        assert.is_true(wm._update_calls[1].updates.enable)
        assert.is_false(wm._update_calls[2].updates.enable)
        ngx.ctx.waf_rule_id = nil
        assert.are.equal(400, (function() ngx.status = 200 json.decode(route("/waf/rules/:id/enable", "POST").h()) return ngx.status end)())
    end)

    it("POST /waf/rules/:id/stage validates the proposal up front", function()
        local stage = route("/waf/rules/:id/stage", "POST")
        ngx.ctx.waf_rule_id = nil
        ngx.status = 200
        assert.are.equal(400, (function() json.decode(stage.h()) return ngx.status end)())
        ngx.ctx.waf_rule_id = "r1"
        req_args = { priority = 99 }
        wm._validate_ok = false
        ngx.status = 200
        assert.are.equal(400, (function() local d = json.decode(stage.h()) return ngx.status end)())
        assert.match("invalid proposed change", (function() ngx.status = 200 return json.decode(stage.h()).message end)())
        ngx.ctx.waf_rule_id = "rX"
        wm._validate_ok = true
        ngx.status = 200
        assert.are.equal(404, (function() json.decode(stage.h()) return ngx.status end)())
        ngx.ctx.waf_rule_id = "r1"
        ngx.status = 200
        local data = json.decode(stage.h())
        assert.are.equal("success", data.ret)
        -- pending slot written and indexed
        local pending = json.decode(cfg():get(PENDING .. "r1"))
        assert.are.equal(99, pending.proposed.priority)
        assert.are.equal("r1", json.decode(cfg():get("waf_pending_index"))[1])
    end)

    it("POST /waf/rules/:id/confirm applies a staged change", function()
        -- stage first
        ngx.ctx.waf_rule_id = "r1"
        req_args = { priority = 42 }
        ngx.status = 200
        json.decode(route("/waf/rules/:id/stage", "POST").h())
        local confirm = route("/waf/rules/:id/confirm", "POST")
        -- confirm without a pending slot -> 404
        ngx.ctx.waf_rule_id = "r2"
        ngx.status = 200
        assert.are.equal(404, (function() json.decode(confirm.h()) return ngx.status end)())
        -- corrupted pending -> 500
        cfg():set(PENDING .. "r2", "{{bad")
        ngx.ctx.waf_rule_id = "r2"
        ngx.status = 200
        assert.are.equal(500, (function() json.decode(confirm.h()) return ngx.status end)())
        -- persist failure keeps the pending slot for a retry
        ngx.ctx.waf_rule_id = "r1"
        cfg():set(PENDING .. "r1", json.encode({ rule_id = "r1", proposed = { priority = 42 } }))
        wm._save_ok = false
        ngx.status = 200
        local d = json.decode(confirm.h())
        assert.are.equal(500, ngx.status)
        assert.match("rule change persist failed", d.message)
        assert.is_not_nil(cfg():get(PENDING .. "r1"))
        -- success: the live rule mutates and the slot is cleared
        wm._save_ok = true
        ngx.status = 200
        local ok = json.decode(confirm.h())
        assert.are.equal("success", ok.ret)
        assert.are.equal(42, wm._rules[1].priority)
        assert.is_nil(cfg():get(PENDING .. "r1"))
        -- stage logged rule_staged first; confirm logs last
        assert.are.equal("rule_change_confirmed", audit_fake.events[#audit_fake.events].action)
    end)

    it("DELETE /waf/rules/:id/pending discards or reports absence", function()
        local discard = route("/waf/rules/:id/pending", "DELETE")
        cfg():set(PENDING .. "r1", json.encode({ rule_id = "r1" }))
        ngx.ctx.waf_rule_id = "r1"
        ngx.status = 200
        local data = json.decode(discard.h())
        assert.are.equal("pending change discarded", data.message)
        ngx.status = 200
        assert.are.equal("no pending change", json.decode(discard.h()).message)
    end)

    it("GET /waf/rules/pending lists via the index and seeds it from legacy entries", function()
        -- index-driven listing
        cfg():set(PENDING .. "r1", json.encode({ rule_id = "r1", proposed = { priority = 1 } }))
        cfg():set("waf_pending_index", json.encode({ "r1" }))
        local data = json.decode(route("/waf/rules/pending", "GET").h())
        assert.are.equal(1, #data.data)
        assert.are.equal("r1", data.data[1].rule_id)
        -- legacy migration: pending entry without an index
        ngx.shared.vn_config:flush_all()
        cfg():set(PENDING .. "r2", json.encode({ rule_id = "r2", proposed = {} }))
        data = json.decode(route("/waf/rules/pending", "GET").h())
        assert.are.equal(1, #data.data)
        assert.are.equal("r2", data.data[1].rule_id)
        -- the index was seeded by the migration
        assert.are.equal("r2", json.decode(cfg():get("waf_pending_index"))[1])
    end)

    it("POST /waf/rules/restore-defaults (additive vs force)", function()
        local data = json.decode(route("/waf/rules/restore-defaults", "POST").h())
        assert.are.equal("success", data.ret)
        assert.match("已恢复 2 条", data.message)
        wm._restore_result = { restored = 0, message = "没有缺失的出厂规则" }
        data = json.decode(route("/waf/rules/restore-defaults", "POST").h())
        assert.are.equal("没有缺失的出厂规则", data.message)
        req_args = { force = true }
        wm._restore_result = { restored = 1, updated = 3 }
        data = json.decode(route("/waf/rules/restore-defaults", "POST").h())
        assert.match("同步 3 条", data.message)
        -- [1]=restored(2), [2]=restored(0), [3]=synced
        assert.are.equal("waf_rules_defaults_synced", audit_fake.events[3].action)
        wm._restore_result = nil
        assert.are.equal(500, (function() ngx.status = 200 json.decode(route("/waf/rules/restore-defaults", "POST").h()) return ngx.status end)())
    end)

    it("POST /waf/rules/accept-factory-actions requires ids", function()
        local h = route("/waf/rules/accept-factory-actions", "POST").h
        assert.are.equal(400, (function() ngx.status = 200 json.decode(h()) return ngx.status end)())
        req_args = { ids = { "r1", "r2" } }
        local data = json.decode(h())
        assert.are.equal("success", data.ret)
        assert.match("已接受出厂动作", data.message)
        assert.match("跳过 1 条", data.message)
        wm._accept_result = nil
        assert.are.equal(400, (function() ngx.status = 200 json.decode(h()) return ngx.status end)())
    end)
end)
