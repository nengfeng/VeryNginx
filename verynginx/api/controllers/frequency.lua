-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : frequency limit controller - stats + rule CRUD

local _M = {}

local config = require "core.config"
local json = require "dkjson"
local audit = require "core.audit"
local helpers = require "api.helpers"

--- Validate that any IP-typed matcher in a rule carries a well-formed address or
--- CIDR. Accepts rule.matcher (table) or rule.matcherJson (string).
local function validate_rule_ip_matchers(rule)
    local matchers = rule.matcher
    if type(matchers) ~= "table" and type(rule.matcherJson) == "string" then
        local okj, m = pcall(json.decode, rule.matcherJson)
        if okj and type(m) == "table" then matchers = m end
    end
    if type(matchers) ~= "table" then return true end
    for name, cond in pairs(matchers) do
        if name == "IP" and type(cond) == "table" and type(cond.value) == "string"
            and cond.value ~= "" then
            -- The IP matcher (matcher/ip.lua) performs only plain string
            -- equality ("=") or regex ("≈") against remote_addr — it has no
            -- CIDR support. A CIDR value like "10.0.0.0/8" would pass the IP
            -- check below but silently never match any request. Reject it so
            -- the user gets immediate feedback instead of a rule that can
            -- never fire.
            if cond.value:find("/") then
                return false, "IP matcher does not support CIDR notation: " .. cond.value
            end
            if not helpers.is_valid_ip(cond.value) then
                return false, "invalid IP in matcher: " .. cond.value
            end
        end
    end
    return true
end

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
    local vimok, vimerr = validate_rule_ip_matchers(rule)
    if not vimok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = vimerr })
    end
    if not rule.id or rule.id == "" then
        local random = require "core.random"
        rule.id = "freq_" .. tostring(ngx.time()) .. "_" .. random.hex(6)
    else
        -- Client-supplied ids flow into the v2 counter dict keys
        -- ("fl:count:" .. enc_id .. ":" .. enc_dim) and the
        -- newline-delimited evidence index. A ":" shifts the key segments, a
        -- "\n" forges index entries, an overlong id bloats keys — mirror the
        -- WAF rule id constraint (§10.13): [A-Za-z0-9_-]{1,64}.
        if type(rule.id) ~= "string" or #rule.id > 64 or not rule.id:match("^[%w_-]+$") then
            ngx.status = 400
            return json.encode({ ret = "failed",
                message = "id must be 1-64 chars of [A-Za-z0-9_-]" })
        end
    end
    local mok, merr = config.atomic_mutate(function(cfg)
        -- Everything is resolved inside the mutator, which receives the config
        -- deep-copied under the save lock. Building the list outside and
        -- assigning it in here wrote the whole group from a pre-lock read, so a
        -- change another worker saved in between was silently discarded.
        if not cfg.rule then cfg.rule = {} end
        local list = cfg.rule.frequency_limit or {}

        -- The panel posts a PARTIAL rule: {id, key, limit, window, code, enable} plus
        -- a matcher only when it has one to send. It has no control for
        -- `action`, and it sends no matcher at all when the box still shows the
        -- '{}' placeholder. Replacing the stored rule with that payload is what
        -- broke twice, and the second break was the worse one:
        --
        --   action  missing -> the shared rule validator rejected the save,
        --              "unknown action 'nil'". Loud, so it was survivable.
        --   matcher missing -> matcher.resolve() returned nil and the plugin
        --              skipped the rule entirely: it counted nothing, blocked
        --              nothing, and only said so once per config generation in
        --              a warning that error_log was set to crit, so nobody saw
        --              it. freq_burst_cc — the 50-per-2s burst limiter, the one
        --              rule positioned to catch a fast CC — was dead on arrival.
        --
        -- So the save is a merge, not a replacement: start from the stored rule
        -- and overlay what the client actually sent. That ends the class of bug
        -- rather than one instance of it, including fields added later that the
        -- panel has no control for yet.
        --
        -- The cost is that omitting a field no longer clears it. That is
        -- acceptable here and is not a workaround: a rate-limit rule with no
        -- matcher matches nothing forever, so "clear the matcher" is not an
        -- operation with a useful meaning, and `enable` is always sent.
        local existing
        for _, r in ipairs(list) do
            if r.id == rule.id then existing = r break end
        end

        local merged = {}
        if existing then
            for k, v in pairs(existing) do merged[k] = v end
        end
        for k, v in pairs(rule) do
            if v ~= nil then merged[k] = v end
        end
        -- _matcher_def is derived from matcher and rebuilt on every save (see
        -- the pre-resolve pass in core/config.lua), and matcher.resolve()
        -- prefers it. Carrying a stale digest alongside a NEW matcher would
        -- make the change invisible, so drop it whenever the client sent one.
        if rule.matcher ~= nil then
            merged._matcher_def = nil
        end
        -- action is required by the shared validator but read by nothing in
        -- plugin/frequency_limit; every stored rule and every template uses
        -- "block", so that is the fallback for a brand-new rule.
        if type(merged.action) ~= "string" or merged.action == "" then
            merged.action = "block"
        end

        local updated = false
        for i, r in ipairs(list) do
            if r.id == merged.id then
                list[i] = merged
                updated = true
                break
            end
        end
        if not updated then
            list[#list + 1] = merged
        end
        cfg.rule.frequency_limit = list
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
    -- Validate IP matcher values (mirrors handle_frequency_rule_save) so a
    -- matcherJson override can't carry a malformed IP (e.g. "999.1.1.1")
    -- that would silently never match and defeat rate limiting.
    local vimok, vimerr = validate_rule_ip_matchers(rule)
    if not vimok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = vimerr })
    end
    -- Save the rule via the same path as handle_frequency_rule_save.
    local mok, merr = config.atomic_mutate(function(cfg)
        -- Resolved under the save lock rather than from a pre-lock read, for
        -- the reason given in handle_frequency_rule_save.
        if not cfg.rule then cfg.rule = {} end
        local list = cfg.rule.frequency_limit or {}
        local updated = false
        for i, r in ipairs(list) do
            if r.id == rule.id then
                list[i] = rule
                updated = true
                break
            end
        end
        if not updated then
            list[#list + 1] = rule
        end
        cfg.rule.frequency_limit = list
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
