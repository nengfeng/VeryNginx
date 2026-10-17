-- -*- coding: utf-8 -*-
-- Regression: editing a rate-limit rule in the panel failed with
--   save failed: rule.frequency_limit[N]: unknown action 'nil'
--
-- The panel's rule editor posts {id, key, limit, window, code, enable, matcher}
-- and has no control for `action`. The save handler replaced the stored rule
-- wholesale, so the action that was already there was discarded; the shared
-- rule validator then rejected the config and nothing was written. Since the
-- validator rejects a missing action for every rule group, and nothing in
-- plugin/frequency_limit ever reads rule.action, the field existed only to
-- satisfy validation — and the only way to supply it was a control the panel
-- does not have. Every edit failed; new rules could not be created either.
--
-- The fix carries an existing rule's action over on edit and defaults to
-- "block" on create, matching what every stored rule and every template uses.

package.path = "verynginx/?.lua;" .. package.path

if not _G.ngx then _G.ngx = {} end
function _G.ngx.log() end
_G.ngx.WARN = 6; _G.ngx.ERR = 5; _G.ngx.INFO = 7
_G.ngx.time = function() return 1700000000 end
_G.ngx.status = 200
_G.ngx.header = { content_type = "application/json; charset=utf-8" }
_G.ngx.var = { uri = "/verynginx/frequency/rules" }

_G.ngx.shared = setmetatable({ _cache = {} }, {
    __index = function(t, name)
        if not t._cache[name] then
            local st = {}
            t._cache[name] = {
                get = function(_, k) return st[k] end,
                set = function(_, k, v) st[k] = v; return true, nil end,
                add = function(_, k, v)
                    if st[k] then return false, "exists" end
                    st[k] = v; return true, nil
                end,
                incr = function(_, k, d, i)
                    if st[k] == nil then st[k] = (i or 0) end
                    st[k] = st[k] + d; return st[k], nil
                end,
                delete = function(_, k) st[k] = nil end,
                expire = function() end,
                flush_all = function() for k in pairs(st) do st[k] = nil end end,
            }
        end
        return t._cache[name]
    end,
})

local mock_config = { rule = { frequency_limit = {} } }

-- Stands in for the real validator: it rejects a rule with no resolvable
-- action, which is what produced the reported error. Returning an error here
-- means atomic_mutate fails exactly as it did in production, so a test cannot
-- pass by silently skipping validation.
local function validate(rules)
    for i, r in ipairs(rules or {}) do
        if type(r.action) ~= "string" or r.action == "" then
            return string.format("rule.frequency_limit[%d]: unknown action '%s'",
                i, tostring(r.action))
        end
    end
    return nil
end

local config_module = {
    load_from_file = function() end,
    report = function() return "{}" end,
    save = function() return true, nil end,
}
setmetatable(config_module, { __index = function(t, k) return mock_config[k] end })

-- Mirrors the real atomic_mutate ordering: deep copy under the lock, run the
-- mutator, THEN validate. The bug needed both halves — a handler that writes
-- a rule without action, and a validator that refuses to save it.
config_module.atomic_mutate = function(mutator)
    local cfg = { rule = { frequency_limit = {} } }
    for i, r in ipairs(mock_config.rule.frequency_limit or {}) do
        local copy = {}
        for k, v in pairs(r) do copy[k] = v end
        cfg.rule.frequency_limit[i] = copy
    end
    local ok, res = pcall(mutator, cfg)
    if not ok then return false, "mutator error: " .. tostring(res) end
    if res == nil then return false, "mutator returned nil" end
    local verr = validate(cfg.rule.frequency_limit)
    if verr then return false, verr end
    mock_config.rule.frequency_limit = cfg.rule.frequency_limit
    return true, nil
end
package.loaded["core.config"] = config_module

package.loaded["core.ip_reputation"] = { is_whitelisted = function() return false end }
package.loaded["core.audit"] = { log = function() end }

local api = require("api.init")
local frequency = require("api.controllers.frequency")
frequency.register(api)

local function find_route(method, path)
    for _, r in ipairs(api.routes) do
        if r.path == path and r.method == method then return r end
    end
end

describe("frequency rule save: action must survive an edit", function()
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

    -- Exactly the payload vn-frequency.js builds.
    local function panel_payload(id, over)
        local r = {
            id = id, key = "ip", limit = 100, window = 60, code = 429, enable = true,
        }
        for k, v in pairs(over or {}) do r[k] = v end
        return r
    end

    local function post_rule(rule)
        _G.ngx.req.get_body_data = function() return dkjson.encode(rule) end
        local route = find_route("POST", "/frequency/rules")
        assert.is_truthy(route, "rule save route registered")
        return dkjson.decode(route.handler())
    end

    local function stored(id)
        for _, r in ipairs(mock_config.rule.frequency_limit or {}) do
            if r.id == id then return r end
        end
    end

    it("saves a new rule the panel posted without an action", function()
        local res = post_rule(panel_payload("freq_new"))
        assert.are.equal("success", res.ret,
            "a new rule must be saveable: " .. tostring(res.message))
        assert.are.equal("block", stored("freq_new").action,
            "and it must carry an action that passes validation")
    end)

    it("keeps the stored action when the panel edits an existing rule", function()
        mock_config.rule.frequency_limit = {
            { id = "freq_existing", key = "ip", limit = 50, window = 60,
              code = 429, action = "block", enable = true },
        }
        local res = post_rule(panel_payload("freq_existing", { limit = 120 }))
        assert.are.equal("success", res.ret,
            "editing must not fail on the missing action: " .. tostring(res.message))
        local r = stored("freq_existing")
        assert.are.equal(120, r.limit, "the edit itself must be applied")
        assert.are.equal("block", r.action, "and the action must have survived")
    end)

    it("preserves a non-default action rather than overwriting it with block", function()
        -- If an operator deliberately configured something else, an edit that
        -- does not mention action must not quietly reset it.
        mock_config.rule.frequency_limit = {
            { id = "freq_custom", key = "ip", limit = 5, window = 60,
              code = 403, action = "log", enable = true },
        }
        local res = post_rule(panel_payload("freq_custom", { limit = 6 }))
        assert.are.equal("success", res.ret)
        assert.are.equal("log", stored("freq_custom").action)
    end)

    it("honours an action the caller does send", function()
        mock_config.rule.frequency_limit = {
            { id = "freq_x", key = "ip", limit = 5, window = 60,
              code = 429, action = "log", enable = true },
        }
        local res = post_rule(panel_payload("freq_x", { action = "block" }))
        assert.are.equal("success", res.ret)
        assert.are.equal("block", stored("freq_x").action,
            "an explicit action must win over the carried-over one")
    end)

    it("replaces the rule in place instead of appending a duplicate", function()
        mock_config.rule.frequency_limit = {
            { id = "freq_dup", key = "ip", limit = 5, window = 60,
              code = 429, action = "block", enable = true },
        }
        post_rule(panel_payload("freq_dup", { limit = 7 }))
        assert.are.equal(1, #mock_config.rule.frequency_limit,
            "an edit must update, never append")
        assert.are.equal(7, mock_config.rule.frequency_limit[1].limit)
    end)

    it("keeps the stored matcher when the panel sends none", function()
        -- The failure this exists for. The panel shows '{}' as a placeholder
        -- when a rule carries a named matcher and has no control for `action`;
        -- when it then posts, finalMatcher stays undefined and `matcher` is
        -- left out of the payload entirely. Replacing the rule dropped it, and
        -- matcher.resolve() then returned nil so the plugin skipped the rule
        -- forever — silently, because error_log was at crit. freq_burst_cc was
        -- dead this way after an ordinary edit.
        mock_config.rule.frequency_limit = {
            { id = "freq_keep", key = "ip", limit = 50, window = 2, code = 429,
              action = "block", enable = true, matcher = { _sorted_conditions = {} } },
        }
        local res = post_rule(panel_payload("freq_keep", { limit = 60 }))
        assert.are.equal("success", res.ret)
        local r = stored("freq_keep")
        assert.are.equal(60, r.limit, "the edit is applied")
        assert.is_truthy(r.matcher,
            "an edit that did not mention the matcher must not delete it")
    end)

it("accepts a matcher the panel does send, and drops the stale digest", function()
        -- _matcher_def is derived from matcher and rebuilt on save, and
        -- matcher.resolve() prefers it. Carrying the old digest alongside a new
        -- matcher would make the change invisible.
        mock_config.rule.frequency_limit = {
            { id = "freq_chg", key = "ip", limit = 5, window = 60, code = 429,
              action = "block", enable = true,
              matcher = { _sorted_conditions = {} },
              _matcher_def = { _sorted_conditions = {}, _matcher_crc = 111 } },
        }
        local res = post_rule(panel_payload("freq_chg", {
            matcher = { URI = { value = "/admin" } },
        }))
        assert.are.equal("success", res.ret)
        local r = stored("freq_chg")
        assert.is_truthy(r.matcher.URI, "the new matcher must be stored")
        assert.are.equal("/admin", r.matcher.URI.value)
        assert.is_nil(r._matcher_def,
            "the derived digest must be dropped, not carried over stale")
    end)

it("still preserves fields the panel has no control for", function()
        mock_config.rule.frequency_limit = {
            { id = "freq_extra", key = "ip", limit = 5, window = 60, code = 429,
              action = "block", enable = true, matcher = {},
              some_future_field = "keep me" },
        }
        local res = post_rule(panel_payload("freq_extra", { limit = 9 }))
        assert.are.equal("success", res.ret)
        assert.are.equal("keep me", stored("freq_extra").some_future_field,
            "an unknown field must survive an edit, not be silently dropped")
    end)

it("reads the rule list under the save lock, not before it", function()
        -- A concurrent save to this group between the handler's read and the
        -- lock used to be discarded, because the whole group was written from
        -- a pre-lock snapshot. Adding a rule inside the mutator must survive.
        local other = { id = "freq_other", key = "ip", limit = 9, window = 60,
                        code = 429, action = "block", enable = true }
        mock_config.rule.frequency_limit = {
            { id = "freq_editing", key = "ip", limit = 5, window = 60,
              code = 429, action = "block", enable = true },
        }

        local real_atomic = config_module.atomic_mutate
        config_module.atomic_mutate = function(mutator)
            -- Simulate another worker committing while this one waits.
            table.insert(mock_config.rule.frequency_limit, other)
            return real_atomic(mutator)
        end

        local res = post_rule(panel_payload("freq_editing", { limit = 11 }))
        config_module.atomic_mutate = real_atomic

        assert.are.equal("success", res.ret)
        assert.is_truthy(stored("freq_other"),
            "a rule saved concurrently must not be lost by this edit")
        assert.are.equal(11, stored("freq_editing").limit)
    end)
end)