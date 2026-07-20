-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : config management - load/save/hot-reload/rollback/validate

local _M = {}
local json = require "dkjson"
local random = require "core.random"

-- URL constants to keep schema lines short
local GEOIP_UPDATE_URL = "https://download.maxmind.com/app/geoip_download"
local GEOIP_CDN_URL = "https://cdn.jsdelivr.net/npm/geolite2-city@latest/GeoLite2-City.mmdb"

-- ---------------------------------------------------------------------------
-- Schema definition
-- ---------------------------------------------------------------------------
local cs = require "core.config_schema"

-- Bottom-up: define leaf schema nodes first, then compose into parents.
local function leaf(t)
    return t
end

_M.schema = {
    version = "2.0",
    fields = {
        base_uri = leaf({ type = "string", default = "/verynginx" }),
        dashboard_host = leaf({ type = "string", default = "" }),
        cookie_prefix = leaf({ type = "string", default = "verynginx" }),
        admin = leaf({ type = "table", default = {} }),
        matcher = leaf({ type = "table", default = {} }),
        rule = leaf({ type = "table", default = {} }),
        backend_upstream = leaf({ type = "table", default = {} }),
        response = leaf({ type = "table", default = {} }),
        plugin = leaf({
            type = "object",
            default = {},
        }),
        -- security: top-level preserve; recursive-merge children
        security = {
            type = "object",
            default = { session_ttl = 28800, csrf = true, rate_limit = { login = "10/m", config_save = "30/m" } },
            children = {
                session_ttl = leaf({ type = "integer", default = 28800, min = 60, max = 86400 * 30 }),
                csrf = leaf({ type = "boolean", default = true }),
                rate_limit = {
                    type = "object",
                    default = { login = "10/m", config_save = "30/m" },
                    children = {
                        login = leaf({ type = "string", default = "10/m" }),
                        config_save = leaf({ type = "string", default = "30/m" }),
                    },
                },
            },
            preserve_unknown = true,
        },
        statistics = leaf({ type = "table", default = {} }),
        observability = leaf({ type = "table", default = {} }),
        body = {
            type = "object",
            default = { max_size = 1048576, max_args = 100, on_error = "fail_closed" },
            children = {
                max_size = leaf({ type = "integer", default = 1048576, min = 1024, max = 104857600 }),
                max_args = leaf({ type = "integer", default = 100, min = 1, max = 10000 }),
                on_error = leaf({ type = "string", default = "fail_closed",
                    enum = { "match", "skip", "fail_closed" } }),
            },
            preserve_unknown = true,
        },
        proxy = {
            type = "object",
            default = { health_check_interval = 5 },
            children = {
                health_check_interval = leaf({ type = "integer", default = 5, min = 1, max = 300 }),
            },
            preserve_unknown = true,
        },
        config_save_lock_ttl = leaf({ type = "integer", default = 60, min = 5, max = 300 }),
        alerting = {
            type = "object",
            default = {
                enabled = false,
                webhook_url = "",
                hit_spike_multiplier = 3.0,
                hit_spike_min_hits = 10,
                fp_pass_rate_threshold = 0.3,
                fp_min_challenges = 5,
                unknown_pattern_min_hits = 5,
                ja3_cross_ip_threshold = 5,
                shared_dict_alert_threshold = 80,
                window_seconds = 360,
            },
            children = {
                enabled           = leaf({ type = "boolean", default = false }),
                webhook_url       = leaf({ type = "string", default = "", pattern = "^https://" }),
                hit_spike_multiplier = leaf({ type = "number", default = 3.0, min = 1.0, max = 100.0 }),
                hit_spike_min_hits   = leaf({ type = "integer", default = 10, min = 1, max = 10000 }),
                fp_pass_rate_threshold = leaf({ type = "number", default = 0.3, min = 0.0, max = 1.0 }),
                fp_min_challenges    = leaf({ type = "integer", default = 5, min = 1, max = 1000 }),
                unknown_pattern_min_hits = leaf({ type = "integer", default = 5, min = 1, max = 1000 }),
                ja3_cross_ip_threshold   = leaf({ type = "integer", default = 5, min = 2, max = 1000 }),
                shared_dict_alert_threshold = leaf({ type = "integer", default = 80, min = 10, max = 99 }),
                window_seconds      = leaf({ type = "integer", default = 360, min = 60, max = 86400 }),
            },
            preserve_unknown = true,
        },
        waf_rules = leaf({ type = "table", default = {} }),
        geoip = {
            type = "object",
            default = {
                enable = false,
                geodb_path = "",
                whitelist = {},
                blocklist = {},
                block_continents = {},
                auto_update = true,
                update_interval_hours = 168,
                license_key = "",
                update_url = "https://download.maxmind.com/app/geoip_download",
                cdn_url = "https://cdn.jsdelivr.net/npm/geolite2-city@latest/GeoLite2-City.mmdb",
                use_cdn = false,
            },
            children = {
                enable              = leaf({ type = "boolean", default = false }),
                geodb_path          = leaf({ type = "string", default = "" }),
                whitelist           = leaf({ type = "array", default = {}, items = "string" }),
                blocklist           = leaf({ type = "array", default = {}, items = "string" }),
                block_continents    = leaf({ type = "array", default = {}, items = "string" }),
                auto_update         = leaf({ type = "boolean", default = true }),
                update_interval_hours = leaf({ type = "integer", default = 168, min = 1, max = 720 }),
                license_key         = leaf({ type = "string", default = "" }),
                update_url          = leaf({ type = "string", default = GEOIP_UPDATE_URL }),
                cdn_url             = leaf({ type = "string", default = GEOIP_CDN_URL }),
                use_cdn             = leaf({ type = "boolean", default = false }),
            },
            preserve_unknown = true,
        },
        fingerprints = {
            type = "object",
            default = { enable = true, auto_block_scanners = true, entries = {} },
            children = {
                enable              = leaf({ type = "boolean", default = true }),
                auto_block_scanners = leaf({ type = "boolean", default = true }),
                entries             = leaf({ type = "array", default = {}, items = "string" }),
            },
            preserve_unknown = true,
        },
        waf_recommender = {
            type = "object",
            default = { enabled = true, min_hits = 10, window_size = 3600, min_patterns = 3 },
            children = {
                enabled     = leaf({ type = "boolean", default = true }),
                min_hits    = leaf({ type = "integer", default = 10, min = 1, max = 10000 }),
                window_size = leaf({ type = "integer", default = 3600, min = 60, max = 86400 }),
                min_patterns = leaf({ type = "integer", default = 3, min = 1, max = 1000 }),
            },
            preserve_unknown = true,
        },
        ip_reputation = {
            type = "object",
            default = {
                enable = false,
                threshold = 25,
                flag_duration = 600,
                window_size = 300,
                slot_size = 60,
                min_requests = 3,
                pending_ttl = 600,
                whitelist = {},
                signals = {
                    waf_challenge = 3,
                    waf_block = 5,
                    not_found = 1,
                    challenge_fail = 5,
                },
                auto_whitelist = {
                    enabled = true,
                    threshold = 3,
                    ttl = 3600,
                    max_entries = 1000,
                },
            },
            children = {
                enable          = leaf({ type = "boolean", default = false }),
                threshold       = leaf({ type = "integer", default = 25, min = 1, max = 10000 }),
                flag_duration   = leaf({ type = "integer", default = 600, min = 60, max = 604800 }),
                window_size     = leaf({ type = "integer", default = 300, min = 60, max = 86400 }),
                slot_size       = leaf({ type = "integer", default = 60, min = 1, max = 3600 }),
                min_requests    = leaf({ type = "integer", default = 3, min = 1, max = 1000 }),
                pending_ttl     = leaf({ type = "integer", default = 600, min = 60, max = 86400 }),
                whitelist       = leaf({ type = "array", default = {}, items = "string" }),
                signals = {
                    type = "object",
                    default = {
                        waf_challenge = 3,
                        waf_block = 5,
                        not_found = 1,
                        challenge_fail = 5,
                    },
                    children = {
                        waf_challenge = leaf({ type = "integer", default = 3, min = 1, max = 100 }),
                        waf_block     = leaf({ type = "integer", default = 5, min = 1, max = 100 }),
                        not_found     = leaf({ type = "integer", default = 1, min = 1, max = 100 }),
                        challenge_fail = leaf({ type = "integer", default = 5, min = 1, max = 100 }),
                    },
                    preserve_unknown = true,
                },
                auto_whitelist = {
                    type = "object",
                    default = {
                        enabled = true,
                        threshold = 3,
                        ttl = 3600,
                        max_entries = 1000,
                    },
                    children = {
                        enabled     = leaf({ type = "boolean", default = true }),
                        threshold   = leaf({ type = "integer", default = 3, min = 1, max = 100 }),
                        ttl         = leaf({ type = "integer", default = 3600, min = 60, max = 604800 }),
                        max_entries = leaf({ type = "integer", default = 1000, min = 1, max = 100000 }),
                    },
                },
            },
            preserve_unknown = true,
        },
        -- ---------------------------------------------------------
        -- kernel_ip_blocking: strictly validated; unknowns rejected
        -- ---------------------------------------------------------
        kernel_ip_blocking = {
            type = "object",
            default = {
                enabled = false,
                mode = "observe",
                topology = "unknown",
                fail_policy = "open",
                helper_socket = "/run/verynginx/firewall-helper.sock",
                scope = "web",
                protected_addresses = {},
                protected_ports = {},
                batch_interval = 1,
                reconcile_interval = 30,
                max_entries = { scanner = 100000, cc = 50000, manual = 10000 },
                scanner = {
                    enabled = true,
                    require_flagged = true,
                    min_hard_blocks = 3,
                    max_ttl = 86400,
                },
                cc = {
                    enabled = true,
                    enforce_ready = false,
                    rule_ids = {},
                    ttl = 300,
                    max_ttl = 1800,
                    min_violation_windows = 3,
                    require_challenge_fail = true,
                },
                ipv4 = { enabled = true },
                ipv6 = { enabled = false, prefix_aggregation = false },
                promotion_rate_limit = {
                    limit = 1000,
                    interval = 60,
                    burst = 1000,
                },
                canary = { scanner_ttl = 60, cc_ttl = 30 },
                emergency_pause = false,
            },
            reject_unknown = true,
            children = {
                enabled = leaf({ type = "boolean", default = false }),
                mode = leaf({ type = "string", default = "observe", enum = { "observe", "enforce" } }),
                topology = leaf({ type = "string", default = "unknown", enum = { "unknown", "direct", "proxied" } }),
                fail_policy = leaf({ type = "string", default = "open", enum = { "open" } }),
                helper_socket = leaf({
                    type = "string",
                    default = "/run/verynginx/firewall-helper.sock",
                    pattern = "^/run/verynginx/firewall%-helper%.sock$",
                }),
                scope = leaf({ type = "string", default = "web", enum = { "web" } }),
                shadow = leaf({ type = "boolean", default = false }),
                protected_addresses = leaf({ type = "array", default = {}, items = "string" }),
                protected_ports = leaf({ type = "array", default = {}, items = "integer", unique_items = true }),
                batch_interval = leaf({ type = "integer", default = 1, min = 1, max = 60 }),
                reconcile_interval = leaf({ type = "integer", default = 30, min = 5, max = 3600 }),
                max_entries = {
                    type = "object",
                    default = { scanner = 100000, cc = 50000, manual = 10000 },
                    children = {
                        scanner = leaf({ type = "integer", default = 100000, min = 1, max = 1000000 }),
                        cc      = leaf({ type = "integer", default = 50000, min = 1, max = 1000000 }),
                        manual  = leaf({ type = "integer", default = 10000, min = 1, max = 1000000 }),
                    },
                },
                scanner = {
                    type = "object",
                    default = { enabled = true, require_flagged = true, min_hard_blocks = 3, max_ttl = 86400 },
                    children = {
                        enabled = leaf({ type = "boolean", default = true }),
                        require_flagged = leaf({ type = "boolean", default = true }),
                        min_hard_blocks = leaf({ type = "integer", default = 3, min = 1, max = 100 }),
                        max_ttl = leaf({ type = "integer", default = 86400, min = 60, max = 604800 }),
                    },
                },
                cc = {
                    type = "object",
                    default = {
                        enabled = true,
                        enforce_ready = false,
                        rule_ids = {},
                        ttl = 300,
                        max_ttl = 1800,
                        min_violation_windows = 3,
                        require_challenge_fail = true,
                    },
                    children = {
                        enabled              = leaf({ type = "boolean", default = true }),
                        enforce_ready        = leaf({ type = "boolean", default = false }),
                        rule_ids = leaf({ type = "array", default = {},
                                            items = "string", unique_items = true }),
                        ttl                  = leaf({ type = "integer", default = 300, min = 60, max = 3600 }),
                        max_ttl              = leaf({ type = "integer", default = 1800, min = 300, max = 604800 }),
                        min_violation_windows = leaf({ type = "integer", default = 3, min = 1, max = 100 }),
                        require_challenge_fail = leaf({ type = "boolean", default = true }),
                    },
                },
                ipv4 = {
                    type = "object",
                    default = { enabled = true },
                    children = {
                        enabled = leaf({ type = "boolean", default = true }),
                    },
                },
                ipv6 = {
                    type = "object",
                    default = { enabled = false, prefix_aggregation = false },
                    children = {
                        enabled = leaf({ type = "boolean", default = false }),
                        prefix_aggregation = leaf({ type = "boolean", default = false }),
                    },
                },
                promotion_rate_limit = {
                    type = "object",
                    default = { limit = 1000, interval = 60, burst = 1000 },
                    children = {
                        limit    = leaf({type = "integer", default = 1000, min = 1, max = 100000}),
                        interval = leaf({type = "integer", default = 60, min = 1, max = 3600}),
                        burst    = leaf({type = "integer", default = 1000, min = 1, max = 100000}),
                    },
                },
                canary = {
                    type = "object",
                    default = { scanner_ttl = 60, cc_ttl = 30 },
                    children = {
                        scanner_ttl = leaf({type = "integer", default = 60, min = 10, max = 600}),
                        cc_ttl      = leaf({type = "integer", default = 30, min = 10, max = 600}),
                    },
                },
                emergency_pause = leaf({ type = "boolean", default = false }),
            },
        },
    }
}

-- ---------------------------------------------------------------------------
-- Deep-table copy (no ref sharing)
-- ---------------------------------------------------------------------------
local function deep_copy(t, depth)
    depth = depth or 0
    if depth > 100 then
        return {}
    end
    if type(t) ~= "table" then
        return t
    end
    local copy = {}
    for k, v in pairs(t) do
        copy[k] = deep_copy(v, depth + 1)
    end
    return copy
end

-- ---------------------------------------------------------------------------
-- Runtime config store (immutable via read-only metatable at end of file)
-- ---------------------------------------------------------------------------
_M.local_hash = nil

local config_data = {}

local function set_config_store(new_data)
    config_data = new_data
end

-- Determine module root at load time from file path
local MODULE_ROOT = (debug.getinfo(1, "S").source or ""):match("^@(.+/)core/config%.lua$")
    or "/opt/verynginx/"

-- ---------------------------------------------------------------------------
-- Path helpers
-- ---------------------------------------------------------------------------
function _M.resolve_path()
    return MODULE_ROOT
end

local function home_path()
    local p = _M.resolve_path()
    if p:match("/$") then
        return p
    end
    return p .. "/"
end

-- ---------------------------------------------------------------------------
-- Config file paths
-- ---------------------------------------------------------------------------
local function config_json_path()
    return home_path() .. "configs/config.json"
end

local function config_default_json_path()
    return home_path() .. "configs/config.default.json"
end

-- ---------------------------------------------------------------------------
-- Normalize defaults: recursively walk schema fields with type/shape checks
-- Keeps backward compatibility with old-style flat schema entries.
-- ---------------------------------------------------------------------------
local function normalize_defaults(config, schema, opts)
    opts = opts or {}
    local result = deep_copy(config)
    local seen_keys = {}
    local all_errors = {}

    for name, field in pairs(schema.fields) do
        seen_keys[name] = true
        local raw_val = result[name]
        -- Route all fields through normalize_node for type/shape checking
        local child_result = cs.normalize_node(field, raw_val, {
            path = name,
            reject_unknown = opts.reject_unknown,
        })
        result[name] = child_result.value
        for _, err in ipairs(child_result.errors or {}) do
            all_errors[#all_errors + 1] = name .. ": " .. err
        end
    end

    if #all_errors > 0 then
        ngx.log(ngx.WARN, "config normalize: " .. table.concat(all_errors, "; "))
    end

    -- Preserve any extra top-level fields not in schema (backward compat)
    -- Callers can opt-in to strict rejection via opts.reject_unknown_top
    if not opts.reject_unknown_top then
        for k, v in pairs(config) do
            if not seen_keys[k] then
                result[k] = deep_copy(v)
            end
        end
    end

    if not result.version then
        result.version = schema.version
    end
    return result
end

-- ---------------------------------------------------------------------------
-- Validate a single rule for reference integrity
-- ---------------------------------------------------------------------------
local _ok_action, _action_init = pcall(require, "action.init")

local function validate_rule(rule, rule_idx, rule_group, config)
    -- Check action is known
    if _ok_action and _action_init then
        local handler = _action_init.get and _action_init.get(rule.action)
        if not handler then
            return false, string.format("rule.%s[%d]: unknown action '%s'", rule_group, rule_idx, tostring(rule.action))
        end
    end

    -- Check matcher reference exists
    if rule.matcher then
        if type(rule.matcher) == "string" then
            if not config.matcher or not config.matcher[rule.matcher] then
                return false, string.format("rule.%s[%d]: matcher '%s' not found in config.matcher",
                    rule_group, rule_idx, rule.matcher)
            end
        elseif type(rule.matcher) == "table" then
            -- inline matcher: check on_body_error values in Args conditions
            for cond_type, cond in pairs(rule.matcher) do
                if cond_type == "Args" and cond.on_body_error then
                    if cond.on_body_error ~= "match" and cond.on_body_error ~= "skip"
                        and cond.on_body_error ~= "fail_closed" then
                        return false, string.format(
                            "rule.%s[%d]: on_body_error must be 'match', 'skip', or 'fail_closed', got '%s'",
                            rule_group, rule_idx, tostring(cond.on_body_error))
                    end
                end
            end
        end
    end

    -- Check response template reference exists
    if rule.response and type(rule.response) == "string" then
        if not config.response or not config.response[rule.response] then
            return false, string.format("rule.%s[%d]: response template '%s' not found in config.response",
                rule_group, rule_idx, rule.response)
        end
    end

    -- Check upstream reference for proxy_pass rules
    if rule.action == "proxy" then
        if not rule.upstream then
            return false, string.format("rule.%s[%d]: proxy action requires 'upstream' field", rule_group, rule_idx)
        end
        local upstream = config.backend_upstream[rule.upstream]
        if not upstream then
            return false, string.format("rule.%s[%d]: upstream '%s' not found in config.backend_upstream",
                rule_group, rule_idx, rule.upstream)
        end
        -- validate upstream has required fields
        if not upstream.nodes or #upstream.nodes == 0 then
            return false, string.format("rule.%s[%d]: upstream '%s' must have at least one node",
                rule_group, rule_idx, rule.upstream)
        end
        if not upstream.health_check then
            return false, string.format("rule.%s[%d]: upstream '%s' must declare health_check",
                rule_group, rule_idx, rule.upstream)
        end
        if not upstream.tls then
            return false, string.format("rule.%s[%d]: upstream '%s' must declare tls config",
                rule_group, rule_idx, rule.upstream)
        end
        if not upstream.timeout then
            return false, string.format("rule.%s[%d]: upstream '%s' must declare timeout config",
                rule_group, rule_idx, rule.upstream)
        end
    end

    -- Check response action has a response reference
    if rule.action == "response" and not rule.response then
        return false, string.format("rule.%s[%d]: response action requires 'response' field", rule_group, rule_idx)
    end

    return true
end

-- ---------------------------------------------------------------------------
-- Validate all rules in a rule group
-- ---------------------------------------------------------------------------
local function validate_rule_group(rules, group_name, config)
    if not rules or type(rules) ~= "table" then
        return true
    end
    local idx = 0
    for _, rule in ipairs(rules) do
        idx = idx + 1
        local ok, err = validate_rule(rule, idx, group_name, config)
        if not ok then
            return false, err
        end
    end
    return true
end

-- ---------------------------------------------------------------------------
-- Compile runtime snapshot: resolve references, pre-compile regex
-- ---------------------------------------------------------------------------
local function compile_runtime_snapshot(compiled)
    -- Mutate the already-normalized config in-place (it's a fresh copy from
    -- normalize_defaults). No need for a second deep_copy.

    -- Pre-resolve matcher references: convert string names to matcher defs
    if compiled.matcher and compiled.rule then
        for _, rules in pairs(compiled.rule) do
            if type(rules) == "table" then
                for _, rule in ipairs(rules) do
                    if type(rule.matcher) == "string" and compiled.matcher[rule.matcher] then
                        rule._matcher_def = compiled.matcher[rule.matcher]
                    elseif type(rule.matcher) == "table" then
                        rule._matcher_def = rule.matcher
                    end
                end
            end
        end
    end

    -- Pre-compute matcher cache CRCs to avoid per-request JSON encode + crc32
    -- Also pre-sort conditions by priority to avoid per-request table allocation + sort
    local matcher_mod = require "matcher.init"
    local cond_order = matcher_mod.condition_order and matcher_mod.condition_order()
    for _, rules in pairs(compiled.rule or {}) do
        if type(rules) == "table" then
            for _, rule in ipairs(rules) do
                local md = rule._matcher_def
                if md then
                    rule._matcher_crc = ngx and ngx.crc32_short and ngx.crc32_short(json.encode(md))
                    if cond_order then
                        local sorted = {}
                        for condition_type, condition in pairs(md) do
                            sorted[#sorted + 1] = { type = condition_type, cond = condition,
                                                    order = cond_order[condition_type] or 50 }
                        end
                        table.sort(sorted, function(a, b) return a.order < b.order end)
                        md._sorted_conditions = sorted
                    end
                end
            end
        end
    end

    return compiled
end

-- ---------------------------------------------------------------------------
-- Validate config schema, reference integrity, and security constraints
-- ---------------------------------------------------------------------------
local function validate_config(config)
    if type(config) ~= "table" then
        return false, "config must be a table"
    end
    if config.version and config.version ~= _M.schema.version then
        return false, "unexpected config version: " .. tostring(config.version)
    end

    -- Admin security check: reject plaintext passwords, require password_hash
    if config.admin then
        for i, a in ipairs(config.admin) do
            if not a.password_hash or a.password_hash == "" then
                return false, string.format("admin[%d]: password_hash is required", i)
            end
            if a.password and a.password == a.password_hash then
                return false, string.format("admin[%d]: password must not be stored as password_hash directly, " ..
                    "use password_hash.verify()", i)
            end
        end
    end

    -- on_body_error global default validation
    if config.body and config.body.on_error then
        local oe = config.body.on_error
        if oe ~= "match" and oe ~= "skip" and oe ~= "fail_closed" then
            return false, "body.on_error must be 'match', 'skip', or 'fail_closed'"
        end
    end

    -- Rule group reference integrity
    if config.rule then
        for group_name, rules in pairs(config.rule) do
            if type(rules) == "table" then
                local ok, err = validate_rule_group(rules, group_name, config)
                if not ok then
                    return false, err
                end
            end
        end
    end

    -- ------------------------------------------------------------------
    -- kernel_ip_blocking: cross-field validation (Design §11.3)
    -- ------------------------------------------------------------------
    local kb = config.kernel_ip_blocking
    if kb and type(kb) == "table" then
        -- interval consistency
        if kb.reconcile_interval and kb.batch_interval then
            if kb.reconcile_interval < kb.batch_interval then
                return false, string.format(
                    "kernel_ip_blocking.reconcile_interval (%d) must be >= batch_interval (%d)",
                    kb.reconcile_interval, kb.batch_interval)
            end
        end

        -- TTL hierarchy
        if kb.cc then
            if kb.cc.max_ttl and kb.cc.ttl and kb.cc.max_ttl < kb.cc.ttl then
                return false, string.format(
                    "kernel_ip_blocking.cc.max_ttl (%d) must be >= cc.ttl (%d)",
                    kb.cc.max_ttl, kb.cc.ttl)
            end
        end
        if kb.scanner then
            local flag_dur = (config.ip_reputation and config.ip_reputation.flag_duration) or 600
            if kb.scanner.max_ttl and kb.scanner.max_ttl < flag_dur then
                return false, string.format(
                    "kernel_ip_blocking.scanner.max_ttl (%d) must be >= ip_reputation.flag_duration (%d)",
                    kb.scanner.max_ttl, flag_dur)
            end
        end

        -- enforce-mode gates
        local _enabled = kb.enabled
        local _mode = kb.mode
        if _enabled == true and _mode == "enforce" then
            if kb.topology ~= "direct" then
                return false, "kernel_ip_blocking: enforce mode requires topology='direct'"
            end
            if not kb.protected_addresses or #kb.protected_addresses == 0 then
                return false, "kernel_ip_blocking: enforce mode requires non-empty protected_addresses"
            end
            if not kb.protected_ports or #kb.protected_ports == 0 then
                return false, "kernel_ip_blocking: enforce mode requires non-empty protected_ports"
            end
            if kb.fail_policy ~= "open" then
                return false, "kernel_ip_blocking: v1 only supports fail_policy='open'"
            end
            if kb.scope ~= "web" then
                return false, "kernel_ip_blocking: v1 only supports scope='web'"
            end
            -- at least one address family must be enabled
            local v4 = kb.ipv4 and kb.ipv4.enabled
            local v6 = kb.ipv6 and kb.ipv6.enabled
            if not v4 and not v6 then
                return false, "kernel_ip_blocking: enforce mode requires at least one enabled address family"
            end
        end

        -- cc.ttl range check (design §11.2)
        if kb.cc and kb.cc.ttl then
            if kb.cc.ttl < 60 or kb.cc.ttl > 3600 then
                return false, "kernel_ip_blocking.cc.ttl must be between 60 and 3600"
            end
        end

        -- enforce_ready is only meaningful when cc.enabled=true (not an error, but warn-log)
        -- cc.enabled && enforce_ready=false is CC observe-only — valid per design §11.5

        -- IPv6 safety knobs
        if kb.ipv6 and kb.ipv6.prefix_aggregation ~= false then
            return false, "kernel_ip_blocking.ipv6.prefix_aggregation must be false in v1"
        end
    end

    -- Alerting webhook URL validation (prevent SSRF)
    if config.alerting and config.alerting.webhook_url and config.alerting.webhook_url ~= "" then
        if not config.alerting.webhook_url:match("^https://") then
            return false, "alerting.webhook_url must use https"
        end
        local host = config.alerting.webhook_url:match("^https://([^/]+)")
        if host then
            host = host:match("^([^:]+)") or host
            if host == "localhost" or host == "127.0.0.1" or host:match("^127%.") then
                return false, "alerting.webhook_url must not target localhost"
            end
            local ip_patterns = {
                "^10%.", "^172%.(1[6-9]%.)", "^172%.2%d%.", "^172%.3[01]%.",
                "^192%.168%.", "^169%.254%.", "^0%.",
            }
            for _, pat in ipairs(ip_patterns) do
                if host:match(pat) then
                    return false, "alerting.webhook_url must not target internal IPs"
                end
            end
        end
    end

    return true
end

-- ---------------------------------------------------------------------------
-- Hot-reload check: compare shared dict hash, zero file I/O on miss
-- ---------------------------------------------------------------------------
function _M.check_update()
    local shared = ngx.shared.vn_config
    if not shared then
        return
    end
    local remote_hash = shared:get("config_hash")
    if remote_hash and remote_hash ~= _M.local_hash then
        if shared:get("config_save_lock") then
            return
        end
        _M.load_from_file()
    end
end

-- ---------------------------------------------------------------------------
-- Load config from file
-- ---------------------------------------------------------------------------
function _M.load_from_file()
    local path = config_json_path()
    local file = io.open(path, "r")
    if not file then
        ngx.log(ngx.WARN, "config file not found at ", path, ", using defaults")
        return false
    end

    local data = file:read("*all")
    file:close()

    local config = json.decode(data)
    if not config then
        -- Try config.default.json as fallback
        ngx.log(ngx.ERR, "config.json decode error, trying config.default.json")
        local default_path = config_default_json_path()
        local default_file = io.open(default_path, "r")
        if default_file then
            local default_data = default_file:read("*all")
            default_file:close()
            config = json.decode(default_data)
            if config then
                ngx.log(ngx.WARN, "config.json invalid, loaded config.default.json as fallback")
                -- Persist the valid default config
                local tmp = path .. ".tmp"
                local out = io.open(tmp, "w")
                if out then
                    out:write(default_data)
                    out:close()
                    os.rename(tmp, path)
                    data = default_data
                end
            end
        end
        if not config then
            ngx.log(ngx.ERR, "config.json and config.default.json both invalid, using schema defaults")
            return false
        end
    end

    -- Auto-generate password_hash for admin entries with empty hash.
    -- Also recovers from the redacted sentinel "(redacted)" left by a prior
    -- bug where GET /config redacted the hash and the Dashboard saved it back.
    local auto_generated = false
    if config.admin then
        local pw_mod = require "core.password_hash"
        for _, a in ipairs(config.admin) do
            if not a.password_hash or a.password_hash == "" or a.password_hash == "(redacted)" then
                local pw = random.hex(12)
                a.password_hash = pw_mod.hash(pw)
                a.password = nil
                ngx.log(ngx.WARN, "config: generated admin password for '", a.user, "' (check config.json)")
                auto_generated = true
            end
        end
    end
    if auto_generated then
        local shared = ngx.shared.vn_config
        local lock_key = "config_auto_save_lock"
        local lock_token = random.bytes(16)
        local lock_ttl = 30

        local got_lock = false
        local do_write = true
        if shared then
            got_lock = shared:add(lock_key, lock_token, lock_ttl)
            if got_lock then
                -- Re-check: another worker may have persisted the file while we computed
                local re_f = io.open(path, "r")
                if re_f then
                    local re_data = re_f:read("*all")
                    re_f:close()
                    local re_config = json.decode(re_data)
                    if re_config and re_config.admin then
                        for _, a in ipairs(re_config.admin) do
                            if a.password_hash and a.password_hash ~= "" then
                                do_write = false
                                data = re_data
                                break
                            end
                        end
                    end
                end
            end
        end

        if do_write then
            local encoded = json.encode(config, { indent = true })
            local tmp = path .. ".tmp"
            local f = io.open(tmp, "w")
            if f then
                f:write(encoded)
                f:close()
                os.rename(tmp, path)
                data = encoded
            end
        elseif not got_lock then
            -- Lost the lock race: re-read the persisted file so our in-memory
            -- password_hash matches what was actually written to disk.
            local re_f = io.open(path, "r")
            if re_f then
                local re_data = re_f:read("*all")
                re_f:close()
                local re_config = json.decode(re_data)
                if re_config and re_config.admin then
                    for _, a in ipairs(re_config.admin) do
                        for _, ca in ipairs(config.admin) do
                            if ca.user == a.user and a.password_hash and a.password_hash ~= "" then
                                ca.password_hash = a.password_hash
                            end
                        end
                    end
                end
            end
        end

        if shared and shared:get(lock_key) == lock_token then
            shared:delete(lock_key)
        end
    end

    local ok, err_or_normalized = validate_config(config)
    if not ok then
        ngx.log(ngx.ERR, "config validation failed: ", err_or_normalized)
        return false
    end

    local normalized = normalize_defaults(config, _M.schema)
    local compiled = compile_runtime_snapshot(normalized)
    set_config_store(compiled)
    _M.local_hash = ngx.md5(data)

    local shared = ngx.shared.vn_config
    if shared then
        shared:set("config_hash", _M.local_hash)
    end

    return true
end

-- ---------------------------------------------------------------------------
-- Backup helpers
-- ---------------------------------------------------------------------------
local function copy_file(src, dst)
    local f_src, err = io.open(src, "rb")
    if not f_src then
        return false, err
    end
    local f_dst, err2 = io.open(dst, "wb")
    if not f_dst then
        f_src:close()
        return false, err2
    end
    local buf = f_src:read(8192)
    while buf do
        f_dst:write(buf)
        buf = f_src:read(8192)
    end
    f_src:close()
    f_dst:close()
    return true
end

local function prune_backups(keep_count)
    local backup_dir = home_path() .. "configs/backups/"
    local files = {}
    local ok, lfs = pcall(require, "lfs")
    if ok then
        for f in lfs.dir(backup_dir) do
            if f:match("^config%.") then
                table.insert(files, f)
            end
        end
    else
        local cmd = 'ls -1t "' .. backup_dir .. '" 2>/dev/null'
        local p = io.popen(cmd, "r")
        if not p then return end
        for f in p:lines() do
            if f:match("^config%.") then
                table.insert(files, f)
            end
        end
        p:close()
    end
    table.sort(files, function(a, b) return a > b end)
    for i = keep_count + 1, #files do
        os.remove(backup_dir .. files[i])
    end
end

local function make_backup(final_path)
    local timestamp = ngx and ngx.time() or os.time()
    local backup_dir = home_path() .. "configs/backups/"
    local backup_path = backup_dir .. "config." .. timestamp .. ".json"
    copy_file(final_path, backup_path)
    prune_backups(10)
    return backup_path
end

-- ---------------------------------------------------------------------------
-- Lock helpers (token-based, with refresh)
-- ---------------------------------------------------------------------------
local function refresh_save_lock(lock_key, lock_token, lock_ttl)
    local shared = ngx.shared.vn_config
    if not shared then
        return
    end
    if shared:get(lock_key) == lock_token then
        shared:expire(lock_key, lock_ttl)
    end
end

local function release_save_lock(lock_key, lock_token)
    local shared = ngx.shared.vn_config
    if not shared then
        return
    end
    if shared:get(lock_key) == lock_token then
        shared:delete(lock_key)
    end
end

-- ---------------------------------------------------------------------------
-- Save config: validate + backup + atomic write + activate
-- ---------------------------------------------------------------------------
function _M.save(config, opts)
    local shared = ngx.shared.vn_config
    local lock_key = "config_save_lock"
    local lock_ttl = math.max((config and config.config_save_lock_ttl) or 60, 5)
    local skip_lock = opts and opts._skip_lock
    local lock_token

    if shared and not skip_lock then
        lock_token = random.bytes(16)
        local locked = shared:add(lock_key, lock_token, lock_ttl)
        if not locked then
            return false, "config save is already running"
        end
    end

    -- Password complexity check before auto-hashing.
    -- Also reject the redacted sentinel "(redacted)" that GET /config returns
    -- — saving it would overwrite the real hash and lock out all admins.
    if config.admin then
        for i, a in ipairs(config.admin) do
            if a.password_hash == "(redacted)" then
                release_save_lock(lock_key, lock_token)
                return false, string.format(
                    "admin[%d]: password_hash is the redacted sentinel '(redacted)' " ..
                    "(load config, edit, then save — do not reuse the redacted value)", i)
            end
            if a.password and a.password ~= "" then
                if #a.password < 8 then
                    release_save_lock(lock_key, lock_token)
                    return false, "admin password must be at least 8 characters"
                end
                if not a.password:find("[A-Z]") then
                    release_save_lock(lock_key, lock_token)
                    return false, "admin password must contain at least one uppercase letter"
                end
                if not a.password:find("[a-z]") then
                    release_save_lock(lock_key, lock_token)
                    return false, "admin password must contain at least one lowercase letter"
                end
                if not a.password:find("[0-9]") then
                    release_save_lock(lock_key, lock_token)
                    return false, "admin password must contain at least one digit"
                end
                if not a.password:find("[^A-Za-z0-9]") then
                    release_save_lock(lock_key, lock_token)
                    return false, "admin password must contain at least one special character"
                end
            end
        end
    end

    -- Hash plaintext passwords in admin entries before validation.
    -- Returns (ok, err_msg) so pcall + inner check both surface errors.
    local ok_hash, hash_ok, hash_err = pcall(function()
        local password_hash_mod = require "core.password_hash"
        if not password_hash_mod or not password_hash_mod.hash then
            return false, "password_hash module unavailable"
        end
        if config.admin then
            for i, a in ipairs(config.admin) do
                if a.password and a.password ~= "" then
                    local hashed = password_hash_mod.hash(a.password)
                    if not hashed or hashed == "" then
                        return false, string.format("admin[%d]: password hash() returned nil", i)
                    end
                    a.password_hash = hashed
                    a.password = nil
                end
            end
        end
        return true, nil
    end)
    if not ok_hash or not hash_ok then
        release_save_lock(lock_key, lock_token)
        -- hash_err (inner return) or ok_hash itself (pcall error message)
        local msg = hash_err or (not ok_hash and tostring(hash_ok)) or "admin password hashing failed"
        return false, msg
    end

    -- validate
    local ok, err_or_normalized = validate_config(config)
    if not ok then
        release_save_lock(lock_key, lock_token)
        return false, err_or_normalized
    end

    local normalized = normalize_defaults(config, _M.schema)
    local compiled = compile_runtime_snapshot(normalized)

    -- encode and hash
    local ok_enc, encoded = pcall(json.encode, normalized, { indent = true })
    if not ok_enc then
        release_save_lock(lock_key, lock_token)
        return false, "encode failed: " .. tostring(encoded)
    end
    local new_hash = ngx.md5(encoded)

    -- prepare file paths
    local final_path = config_json_path()
    local tmp_path = final_path .. ".tmp"
    make_backup(final_path)
    refresh_save_lock(lock_key, lock_token, lock_ttl)

    -- write tmp file
    local file, err_write = io.open(tmp_path, "w")
    if not file then
        release_save_lock(lock_key, lock_token)
        return false, "cannot open temp file: " .. tostring(err_write)
    end
    file:write(encoded)
    file:close()
    refresh_save_lock(lock_key, lock_token, lock_ttl)

    -- atomic rename
    local ok_rename, err_rename = os.rename(tmp_path, final_path)
    if not ok_rename then
        release_save_lock(lock_key, lock_token)
        return false, "rename failed: " .. tostring(err_rename)
    end

    -- capture previous config for lifecycle transition hooks
    local previous = deep_copy(config_data)

    -- activate
    set_config_store(compiled)
    _M.local_hash = new_hash
    if shared then
        shared:set("config_backup_latest", final_path .. ".bak")
        shared:set("config_hash", new_hash)
    end
    release_save_lock(lock_key, lock_token)

    -- Post-activation: kernel blocking lifecycle transitions (Design §10.5).
    -- Failures must not roll back the already-activated config.
    pcall(function()
        local life = require "core.kernel_blocking.lifecycle"
        life.on_config_activated(previous, compiled)
    end)

    return true
end

-- ---------------------------------------------------------------------------
-- Atomic mutate: read-modify-save under the config_save lock.
-- Prevents lost updates when concurrent workers modify the same field
-- (e.g. whitelist add/remove races, B4).
-- @param mutator function(cfg) -> modified_cfg | (nil, error)
-- @return ok, error?
-- ---------------------------------------------------------------------------
function _M.atomic_mutate(mutator)
    local shared = ngx.shared.vn_config
    local lock_key = "config_save_lock"
    local lock_ttl = 60
    local lock_token = random.bytes(16)

    if shared then
        local locked = shared:add(lock_key, lock_token, lock_ttl)
        if not locked then
            return false, "config save is already running"
        end
    end

    -- Read current config from the runtime store inside the lock.
    -- (Reading from runtime — not disk — avoids file path issues in
    -- test environments; the lock ensures serialization so worker B
    -- always sees worker A's saved changes.)
    local current = deep_copy(config_data)
    if not current then
        release_save_lock(lock_key, lock_token)
        return false, "no active config"
    end

    -- Apply mutation
    local ok, modified, merr = pcall(mutator, current)
    if not ok then
        release_save_lock(lock_key, lock_token)
        return false, "mutator error: " .. tostring(modified)
    end
    if modified == nil then
        -- merr is the error from mutator
        release_save_lock(lock_key, lock_token)
        return false, tostring(merr or "mutator returned nil")
    end

    -- Save (skip lock acquisition — we already hold it)
    local save_ok, save_err = _M.save(modified, { _skip_lock = true })
    if not save_ok then
        release_save_lock(lock_key, lock_token)
        return false, tostring(save_err)
    end
    release_save_lock(lock_key, lock_token)
    return true
end
function _M.rollback(backup_path)
    local file, err = io.open(backup_path, "r")
    if not file then
        return false, "backup not found: " .. tostring(err)
    end
    local data = file:read("*all")
    file:close()
    local config = json.decode(data)
    if not config then
        return false, "backup decode failed"
    end
    return _M.save(config)
end

-- ---------------------------------------------------------------------------
-- Report current config as JSON string
-- ---------------------------------------------------------------------------
function _M.report()
    return json.encode(config_data)
end

-- Exposed for testing (not part of public API)
function _M.validate_config(config)
    return validate_config(config)
end

-- Make config read-only (except for local_hash which is mutated at runtime)
setmetatable(_M, {
    __index = function(_, k)
        if k == "local_hash" then
            return rawget(_M, "local_hash")
        end
        return config_data[k]
    end,
    __newindex = function(t, k, v)
        if k == "local_hash" then
            rawset(t, k, v)
            return
        end
        error("config is readonly, use config.save()")
    end,
    __pairs = function()
        return pairs(config_data)
    end,
})

return _M