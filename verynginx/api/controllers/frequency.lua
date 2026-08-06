-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : frequency limit controller - stats + rule CRUD

local _M = {}

local config = require "core.config"
local json = require "dkjson"
local audit = require "core.audit"

local function handle_frequency_stats()
    local shared = ngx.shared.frequency_limit
    if not shared then
        return json.encode({ ret = "success", data = {} })
    end
    local keys = shared:get_keys(200)
    local stats = {}
    for _, k in ipairs(keys) do
        if k:sub(1, 3) == "fl:" then
            local val = shared:get(k)
            if val and val > 0 then
                stats[#stats + 1] = { key = k, count = val }
            end
        end
    end
    table.sort(stats, function(a, b) return a.count > b.count end)
    return json.encode({ ret = "success", data = stats })
end

local function handle_frequency_rules()
    local rules = config.rule.frequency_limit or {}
    return json.encode({ ret = "success", data = rules })
end

local function handle_frequency_rule_save()
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or raw == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end
    local ok, rule = pcall(json.decode, raw)
    if not ok or type(rule) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid JSON" })
    end
    if not rule.id or rule.id == "" then
        local random = require "core.random"
        rule.id = "freq_" .. tostring(ngx.time()) .. "_" .. random.hex(6)
    end
    if not config.rule then config.rule = {} end
    local rules = config.rule.frequency_limit or {}
    local updated = false
    for i, r in ipairs(rules) do
        if r.id == rule.id then
            rules[i] = rule
            updated = true
            break
        end
    end
    if not updated then
        rules[#rules + 1] = rule
    end
    local mok, merr = config.atomic_mutate(function(cfg)
        cfg.rule.frequency_limit = rules
        return cfg
    end)
    if not mok then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "save failed: " .. (merr or "unknown") })
    end
    audit.log("frequency_rule_saved", rule.id, "-")
    return json.encode({ ret = "success", data = { id = rule.id } })
end

local function handle_frequency_rule_delete()
    local rule_id = ngx.ctx.waf_rule_id
    if not rule_id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "rule id required" })
    end
    local rules = config.rule.frequency_limit or {}
    local filtered = {}
    for _, r in ipairs(rules) do
        if r.id ~= rule_id then
            filtered[#filtered + 1] = r
        end
    end
    local mok, merr = config.atomic_mutate(function(cfg)
        cfg.rule.frequency_limit = filtered
        return cfg
    end)
    if not mok then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "save failed: " .. (merr or "unknown") })
    end
    audit.log("frequency_rule_deleted", rule_id, "-")
    return json.encode({ ret = "success", message = "rule deleted" })
end

local function handle_template_list()
    local templates = require "core.frequency_templates"
    return json.encode({ ret = "success", data = templates.list() })
end

local function handle_template_get()
    local name = ngx.ctx.waf_rule_id
    if not name or name == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "template name required" })
    end
    local templates = require "core.frequency_templates"
    local t = templates.get(name)
    if not t then
        ngx.status = 404
        return json.encode({ ret = "failed", message = "template not found: " .. name })
    end
    return json.encode({ ret = "success", data = t })
end

local function handle_template_apply()
    local id = ngx.ctx.waf_rule_id
    if not id or id == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "template name required" })
    end
    local templates = require "core.frequency_templates"
    -- Read optional overrides from body.
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    local overrides = {}
    if raw and raw ~= "" then
        local ok, t = pcall(json.decode, raw)
        if ok and type(t) == "table" then overrides = t end
    end
    local rule, err = templates.apply(id, overrides)
    if not rule then
        ngx.status = 400
        return json.encode({ ret = "failed", message = err })
    end
    -- Save the rule via the same path as handle_frequency_rule_save.
    if not config.rule then config.rule = {} end
    local rules = config.rule.frequency_limit or {}
    local updated = false
    for i, r in ipairs(rules) do
        if r.id == rule.id then
            rules[i] = rule
            updated = true
            break
        end
    end
    if not updated then
        rules[#rules + 1] = rule
    end
    local mok, merr = config.atomic_mutate(function(cfg)
        cfg.rule.frequency_limit = rules
        return cfg
    end)
    if not mok then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "save failed: " .. (merr or "unknown") })
    end
    audit.log("frequency_rule_from_template", rule.id, id)
    return json.encode({ ret = "success", data = { id = rule.id, rule = rule } })
end

function _M.register(api)
    api.register("GET",    "/frequency/stats",              handle_frequency_stats,       true)
    api.register("GET",    "/frequency/rules",              handle_frequency_rules,       true)
    api.register("POST",   "/frequency/rules",              handle_frequency_rule_save,   true)
    api.register("DELETE", "/frequency/rules/:id",          handle_frequency_rule_delete, true)
    api.register("GET",    "/frequency/templates",          handle_template_list,         true)
    api.register("GET",    "/frequency/templates/:id",      handle_template_get,          true)
    api.register("POST",   "/frequency/templates/:id",      handle_template_apply,        true)
end

return _M
