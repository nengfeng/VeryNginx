-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : default WAF filter rules - SQL injection, path traversal, scanner detection

local _M = {}

-- Default matchers for built-in security rules
_M.default_matchers = {
    attack_sql = {
        Args = {
            name_operator = "*",
            operator = "≈",
            value = "(select\\s+.+from|union\\s+.+select|sleep\\s*\\(|load_file\\s*\\()",
            on_body_error = "fail_closed"
        }
    },
    attack_backup = {
        URI = {
            operator = "≈",
            value = "\\.(htaccess|bash_history|ssh|sql|bak|old|swp)$"
        }
    },
    attack_scan = {
        UserAgent = {
            operator = "≈",
            value = "(nmap|w3af|netsparker|nikto|fimap|wget|curl|python-requests|go-http-client)"
        }
    },
    attack_code = {
        URI = {
            operator = "≈",
            value = "\\.(git|svn|env|git/config|svn/entries)"
        }
    },
    attack_path_traversal = {
        URI = {
            operator = "≈",
            value = "(\\.\\./|\\.\\.\\\\)"
        }
    }
}

-- Default filter rules referencing the matchers above
_M.default_rules = {
    { enable = true, matcher = "attack_sql", action = "block", code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_backup", action = "block", code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_scan", action = "block", code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_code", action = "block", code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_path_traversal", action = "block", code = 403, response = "forbidden_json" },
}

return _M