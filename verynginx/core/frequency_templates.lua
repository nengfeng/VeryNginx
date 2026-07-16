-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-16
-- @Author  : VeryNginx v2
-- @Disc    : Frequency rule template library — preset scenarios for common
--             rate-limiting use cases (login brute-force, API abuse, etc).

local _M = {}

local json = require "dkjson"

-- ---------------------------------------------------------------------------
-- Template definitions.
-- Each template produces a frequency_limit rule table when applied.
-- `apply(name, overrides?)` returns the rule table or nil + err.
-- ---------------------------------------------------------------------------
local TEMPLATES = {
    login_bruteforce = {
        name = "login_bruteforce",
        label = "Login Brute-Force Protection",
        description = "Strict per-IP limit on login endpoints. Blocks after 5 attempts per minute.",
        rule = {
            id = "freq_login_bruteforce",
            key = "ip",
            limit = 5,
            window = 60,
            code = 429,
            enable = true,
            matcherJson = '{"URI":{"operator":"≈","value":"/login"}}',
        },
    },
    api_abuse = {
        name = "api_abuse",
        label = "API Rate Limit",
        description = "Standard per-IP API rate limit. 60 requests/minute with 429 response.",
        rule = {
            id = "freq_api_abuse",
            key = "ip",
            limit = 60,
            window = 60,
            code = 429,
            enable = true,
            matcherJson = '{"URI":{"operator":"≈","value":"/api/"}}',
        },
    },
    crawler = {
        name = "crawler",
        label = "Crawler / Scanner",
        description = "Per-IP+UA limit with challenge action. 30 req/min triggers JS challenge.",
        rule = {
            id = "freq_crawler",
            key = "ip",
            limit = 30,
            window = 60,
            code = 200,
            enable = true,
            matcherJson = "{}",
        },
    },
    global_cc = {
        name = "global_cc",
        description = "Global CC protection. 300 req/min per IP with challenge.",
        label = "Global CC Protection",
        rule = {
            id = "freq_global_cc",
            key = "ip",
            limit = 300,
            window = 60,
            code = 200,
            enable = true,
            matcherJson = "{}",
        },
    },
    sensitive_api = {
        name = "sensitive_api",
        label = "Sensitive Endpoints",
        description = "Strict limit on password reset, SMS, email endpoints. 10 req/min.",
        rule = {
            id = "freq_sensitive_api",
            key = "ip",
            limit = 10,
            window = 60,
            code = 429,
            enable = true,
            matcherJson = '{"URI":{"operator":"≈","value":"/reset-password"}}',
        },
    },
    per_user = {
        name = "per_user",
        label = "Per-User Limit",
        description = "Rate limit by authenticated user (not IP). 100 req/min per user.",
        rule = {
            id = "freq_per_user",
            key = "user",
            limit = 100,
            window = 60,
            code = 429,
            enable = true,
            matcherJson = "{}",
        },
    },
    host_based = {
        name = "host_based",
        label = "Per-Host Limit",
        description = "Rate limit by Host header. Useful for multi-tenant APIs.",
        rule = {
            id = "freq_host_based",
            key = "host",
            limit = 120,
            window = 60,
            code = 429,
            enable = true,
            matcherJson = "{}",
        },
    },
    aggressive_block = {
        name = "aggressive_block",
        label = "Aggressive Block",
        description = "Very strict: 3 req/min, immediate block. Use for known-bad patterns.",
        rule = {
            id = "freq_aggressive",
            key = "ip",
            limit = 3,
            window = 60,
            code = 403,
            enable = true,
            matcherJson = "{}",
        },
    },
}

-- List all available templates (metadata only, no rule details).
function _M.list()
    local result = {}
    for name, t in pairs(TEMPLATES) do
        result[#result + 1] = {
            name = name,
            label = t.label,
            description = t.description,
        }
    end
    table.sort(result, function(a, b) return a.name < b.name end)
    return result
end

-- Get a single template's full rule (with optional field overrides).
-- Returns rule_table or nil, error_message.
function _M.apply(name, overrides)
    local t = TEMPLATES[name]
    if not t then
        return nil, "unknown template: " .. tostring(name)
    end
    -- Deep-copy the rule so callers can mutate freely.
    local rule = json.decode(json.encode(t.rule))
    if overrides and type(overrides) == "table" then
        for k, v in pairs(overrides) do
            rule[k] = v
        end
    end
    -- Always regenerate id if overridden or to avoid collisions.
    if rule.id == nil or rule.id == "" then
        rule.id = "freq_" .. tostring(ngx.time())
    end
    return rule, nil
end

-- Get a single template's metadata + default rule (for preview).
function _M.get(name)
    local t = TEMPLATES[name]
    if not t then return nil end
    return {
        name = t.name,
        label = t.label,
        description = t.description,
        rule = json.decode(json.encode(t.rule)),
    }
end

return _M
