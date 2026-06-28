-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-28
-- @Author  : VeryNginx v2
-- @Disc    : One-time migration script: convert existing config rules to
--            waf-rule-manager format. Run from init_by_lua_block or CLI.
--
-- Usage:
--   init_by_lua_block {
--       local ok, err = require("docs.migrations.migrate_waf_rules").run()
--       if ok then ngx.log(ngx.NOTICE, "WAF migration: success") end
--   }
--
-- Note: config module has a read-only metatable. You cannot set fields
-- directly on it. Instead, build a full config object and call config.save().

local _M = {}
local json = require("dkjson")
local config = require("core.config")

local CATEGORY_MAP = {
    attack_sqli           = "sqli",
    attack_backup         = "path_traversal",
    attack_scanner        = "scanner",
    attack_code_leak      = "lfi",
    attack_path_traversal = "path_traversal",
    attack_rce            = "rce",
}

local SEVERITY_MAP = {
    attack_sqli           = "critical",
    attack_backup         = "high",
    attack_scanner        = "medium",
    attack_code_leak      = "high",
    attack_path_traversal = "critical",
    attack_rce            = "critical",
}

function _M.run()
    -- Check if waf-rules.json already exists
    local waf_path = config.resolve_path() .. "configs/waf-rules.json"
    local f = io.open(waf_path, "r")
    if f then
        f:close()
        -- File exists: check if it has content
        local content = f and io.open(waf_path, "r") or nil
        if content then
            local data = content:read("*all")
            content:close()
            if data and #data > 10 then
                ngx.log(ngx.NOTICE, "WAF migration: waf-rules.json already exists, skipping")
                return true
            end
        end
    end

    -- Read rules from config (if present)
    local cfg = config.report()
    local ok, decoded = pcall(json.decode, cfg)
    if not ok or not decoded then
        ngx.log(ngx.NOTICE, "WAF migration: no config data, skipping")
        return false, "no config data"
    end

    local existing_rules = decoded.waf_rules
    if existing_rules and existing_rules.rules and #existing_rules.rules > 0 then
        ngx.log(ngx.NOTICE, "WAF migration: rules already in config, skipping")
        return true
    end

    -- Try to load from filter.rules fallback
    local ok2, rules_module = pcall(require, "plugin.filter.rules")
    if not ok2 or not rules_module then
        ngx.log(ngx.NOTICE, "WAF migration: no filter.rules module, skipping")
        return true
    end

    local default_rules = rules_module.default_matchers or rules_module.default_rules
    if not default_rules or type(default_rules) ~= "table" or #default_rules == 0 then
        ngx.log(ngx.NOTICE, "WAF migration: no default rules to migrate, skipping")
        return true
    end

    -- Convert rules
    local waf_rules = {
        version = 1,
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        rules = {}
    }

    for _, rule in ipairs(default_rules) do
        local matcher_name = rule.matcher or rule.name or "unknown"
        local category = CATEGORY_MAP[matcher_name] or "custom"
        local severity = SEVERITY_MAP[matcher_name] or "medium"

        table.insert(waf_rules.rules, {
            id = matcher_name .. "_default",
            name = matcher_name:gsub("_", " "):gsub("^%l", string.upper),
            description = "Built-in rule migrated from " .. matcher_name,
            category = category,
            severity = severity,
            enable = rule.enable ~= false,
            priority = 100,
            matcher = rule.matcher,
            action = rule.action or "block",
            code = rule.code or 403,
            response = rule.response,
            tags = { matcher_name },
            created_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            hit_count = 0,
            version = 1
        })
    end

    -- Save rules via waf-rule-manager
    local waf_manager = require("waf-rule-manager")
    local save_ok, save_err = waf_manager.save_rules(waf_rules.rules)
    if not save_ok then
        ngx.log(ngx.ERR, "WAF migration: save failed: ", tostring(save_err))
        return false, save_err
    end

    ngx.log(ngx.NOTICE, "WAF migration: migrated " .. #waf_rules.rules .. " rules to waf-rules.json")
    return true
end

return _M