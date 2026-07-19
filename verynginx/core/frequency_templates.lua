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
        label = "登录爆破防护",
        description = "严格限制登录接口，单 IP 每分钟 5 次，超限直接拦截。适用于 /login 等认证页面。",
        rule = {
            id = "freq_login_bruteforce",
            action = "block",
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
        label = "API 限流",
        description = "标准 API 层限速，单 IP 每分钟 60 次，返回 429。保护 /api/ 前缀接口。",
        rule = {
            id = "freq_api_abuse",
            action = "block",
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
        label = "爬虫 / 扫描",
        description = "按 IP+UA 限速，单 IP 每分钟 30 次即触发 JS 人机验证（不直接封禁）。",
        rule = {
            id = "freq_crawler",
            action = "block",
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
        label = "全局 CC 防护",
        description = "全局流量兜底，单 IP 每分钟 300 次触发 JS 验证。",
        rule = {
            id = "freq_global_cc",
            action = "block",
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
        label = "敏感接口",
        description = "密码重置、短信、邮箱等高敏感接口，单 IP 每分钟 10 次。",
        rule = {
            id = "freq_sensitive_api",
            action = "block",
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
        label = "按用户限速",
        description = "按认证用户身份（非 IP）限速，单用户每分钟 100 次，防止账号内滥用。",
        rule = {
            id = "freq_per_user",
            action = "block",
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
        label = "按域名限速",
        description = "按 Host 请求头限速，适用于多租户 API 场景，单域名每分钟 120 次。",
        rule = {
            id = "freq_host_based",
            action = "block",
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
        label = "严格拦截",
        description = "极严格：单 IP 每分钟仅 3 次，超限立即返回 403。适用于已知恶意模式。",
        rule = {
            id = "freq_aggressive",
            action = "block",
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
