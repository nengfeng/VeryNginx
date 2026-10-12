-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : default WAF filter rules - SQL injection, path traversal, scanner detection

local _M = {}

-- Default matchers for built-in security rules.
-- These only activate when waf-rules.json is missing/corrupt; keep them
-- aligned with the v10 factory philosophy: tight patterns (no bare
-- "select.+from", no bare "zap" matching "Zapier"), narrow backup
-- extensions (real backup/sensitive suffixes only, incl. .sql.gz).
_M.default_matchers = {
    attack_sqli = {
        Args = {
            name_operator = "*",
            operator = "≈",
            value = "(\\bunion\\b[\\s/*]+(?:all[\\s/*]+)?select\\b|" ..
                "\\bsleep\\s*\\(|\\bload_file\\s*\\(|\\bexec\\s*\\(|" ..
                "\\bxp_cmdshell\\b|\\binformation_schema\\b|\\b1\\s*=\\s*1\\b|" ..
                "'\\s*or\\s*'|\\b0x[0-9a-f]{8,}\\b)",
            on_body_error = "fail_closed"
        }
    },
    attack_backup = {
        URI = {
            operator = "≈",
            value = "\\.(?:bak|old|save|swp|tar\\.gz|sql\\.gz|htaccess|htpasswd|bash_history|ssh)$"
        }
    },
    attack_scanner = {
        UserAgent = {
            operator = "≈",
            -- "zap\\b": a bare "zap" also matches "Zapier" (false positive)
            value = "(nmap|w3af|netsparker|nikto|acunetix|nessus|openvas|fimap|sqlmap|hydra|medusa|burpsuite|zap\\b)"
        }
    },
    attack_code_leak = {
        URI = {
            operator = "≈",
            value = "(\\.git/|\\.svn/entries|\\.env\\b|/vendor/|/composer\\.json|" ..
                "/package\\.json|/node_modules/|/wp-config\\.php|config\\.php\\b|WEB-INF/web\\.xml)"
        }
    },
    attack_path_traversal = {
        URI = {
            operator = "≈",
            value = "(\\.\\./|\\.\\.\\\\)"
        }
    },
    attack_rce = {
        URI = {
            operator = "≈",
            value = "(\\beval\\s*\\(|\\bsystem\\s*\\(|\\bpassthru\\s*\\(|" ..
                "\\bexec\\s*\\(|\\bassert\\s*\\(|\\bbase64_decode\\s*\\()"
        }
    },
}

-- Default filter rules referencing the matchers above
_M.default_rules = {
    { enable = true, matcher = "attack_sqli", action = "block", code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_backup", action = "block", code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_scanner", action = "block", code = 429, response = "forbidden_json" },
    { enable = true, matcher = "attack_code_leak", action = "challenge", code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_path_traversal", action = "block", code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_rce", action = "block", code = 403, response = "forbidden_json" },
}

-- Load rules: priority from waf-rule-manager, fallback to defaults
function _M.load_rules()
    local ok, waf_manager = pcall(require, "waf-rule-manager")
    if ok and waf_manager then
        local rules_obj = waf_manager.load_rules()
        if rules_obj and rules_obj.rules and #rules_obj.rules > 0 then
            return rules_obj.rules
        end
    end
    -- Fallback: convert default rules to waf format
    local fallback = {}
    for _, rule in ipairs(_M.default_rules) do
        local m = rule.matcher
        table.insert(fallback, {
            id = m .. "_default",
            name = m:gsub("_", " "):gsub("^%l", string.upper),
            category = "custom",
            severity = "medium",
            enable = rule.enable ~= false,
            priority = 100,
            matcher = rule.matcher,
            action = rule.action,
            code = rule.code or 403,
            response = rule.response,
            tags = { m },
            hit_count = 0,
            version = 1
        })
    end
    return fallback
end

return _M