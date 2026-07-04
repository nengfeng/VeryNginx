-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : config management - load/save/hot-reload/rollback/validate

local _M = {}
local json = require "dkjson"
local random = require "core.random"

-- ---------------------------------------------------------------------------
-- Schema definition
-- ---------------------------------------------------------------------------
_M.schema = {
    version = "2.0",
    fields = {
        base_uri = { type = "string", default = "/verynginx" },
        dashboard_host = { type = "string", default = "" },
        cookie_prefix = { type = "string", default = "verynginx" },
        admin = { type = "table", default = {} },
        matcher = { type = "table", default = {} },
        rule = { type = "table", default = {} },
        backend_upstream = { type = "table", default = {} },
        response = { type = "table", default = {} },
        plugin = { type = "table", default = {} },
        security = { type = "table", default = { session_ttl = 28800 } },
        statistics = { type = "table", default = {} },
        observability = { type = "table", default = {} },
        body = { type = "table", default = { max_size = 1048576, max_args = 100, on_error = "fail_closed" } },
        proxy = { type = "table", default = { health_check_interval = 5 } },
        config_save_lock_ttl = { type = "number", default = 60 },
        alerting = { type = "table", default = {
            enabled = false,
            webhook_url = "",
            hit_spike_multiplier = 3.0,
            hit_spike_min_hits = 10,
            fp_pass_rate_threshold = 0.3,
            fp_min_challenges = 5,
            unknown_pattern_min_hits = 5,
            ja3_cross_ip_threshold = 5,
            window_seconds = 360,
        } },
        waf_rules = { type = "table", default = {} },
        ip_reputation = { type = "table", default = {
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
        } },
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
-- Normalize defaults: fill missing fields with schema defaults
-- ---------------------------------------------------------------------------
local function normalize_defaults(config, schema)
    local result = deep_copy(config)
    for name, field in pairs(schema.fields) do
        if result[name] == nil then
            result[name] = deep_copy(field.default)
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
        local upstream = config.backend_upstream and config.backend_upstream[rule.upstream]
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
local function compile_runtime_snapshot(config)
    -- Create a compiled copy with pre-resolved references
    local compiled = deep_copy(config)

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

    -- Pre-compute matcher cache CRCs to avoid per-request dkjson.encode + crc32
    local cjson = require("dkjson")
    for _, rules in pairs(compiled.rule or {}) do
        if type(rules) == "table" then
            for _, rule in ipairs(rules) do
                local md = rule._matcher_def
                if md then
                    local crc = ngx and ngx.crc32_short and ngx.crc32_short(cjson.encode(md))
                    rule._matcher_crc = crc
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

    -- Auto-generate password_hash for admin entries with empty hash
    local auto_generated = false
    if config.admin then
        local pw_mod = require "core.password_hash"
        for _, a in ipairs(config.admin) do
            if not a.password_hash or a.password_hash == "" then
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
function _M.save(config)
    local shared = ngx.shared.vn_config
    local lock_key = "config_save_lock"
    local lock_ttl = math.max((config and config.config_save_lock_ttl) or 10, 5)
    local lock_token = random.bytes(16)

    if shared then
        local locked = shared:add(lock_key, lock_token, lock_ttl)
        if not locked then
            return false, "config save is already running"
        end
    end

    -- Password complexity check before auto-hashing
    if config.admin then
        for _, a in ipairs(config.admin) do
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

    -- Hash plaintext passwords in admin entries before validation
    pcall(function()
        local password_hash_mod = require "core.password_hash"
        if config.admin then
            for _, a in ipairs(config.admin) do
                if a.password and a.password ~= "" then
                    a.password_hash = password_hash_mod.hash(a.password)
                    a.password = nil
                end
            end
        end
    end)

    -- validate
    local ok, err_or_normalized = validate_config(config)
    if not ok then
        release_save_lock(lock_key, lock_token)
        return false, err_or_normalized
    end

    local normalized = normalize_defaults(config, _M.schema)
    local compiled = compile_runtime_snapshot(normalized)

    -- encode and hash
    local encoded = json.encode(normalized, { indent = true })
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

    -- activate
    set_config_store(compiled)
    _M.local_hash = new_hash
    if shared then
        shared:set("config_backup_latest", final_path .. ".bak")
        shared:set("config_hash", new_hash)
    end
    release_save_lock(lock_key, lock_token)

    return true
end

-- ---------------------------------------------------------------------------
-- Rollback: restore from a backup file
-- ---------------------------------------------------------------------------
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