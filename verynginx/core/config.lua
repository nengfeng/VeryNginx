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
        security = { type = "table", default = {} },
        statistics = { type = "table", default = {} },
        observability = { type = "table", default = {} },
        body = { type = "table", default = { max_size = 1048576, max_args = 100, on_error = "fail_closed" } },
        proxy = { type = "table", default = { health_check_interval = 5 } },
        config_save_lock_ttl = { type = "number", default = 60 },
    }
}

-- ---------------------------------------------------------------------------
-- Deep-table copy (no ref sharing)
-- ---------------------------------------------------------------------------
local function deep_copy(t)
    if type(t) ~= "table" then
        return t
    end
    local copy = {}
    for k, v in pairs(t) do
        copy[k] = deep_copy(v)
    end
    return copy
end

-- Make a table read-only via a proxy metatable.
-- The underlying storage (`store`) is still replaceable by swapping the closure.
local function make_readonly(store_ref)
    return setmetatable({}, {
        __index = function(_, k)
            return store_ref[k]
        end,
        __newindex = function(_, k, v)
            error("config is readonly, use config.save()")
        end,
        __pairs = function()
            return pairs(store_ref)
        end,
        __len = function()
            return #store_ref
        end,
    })
end

-- ---------------------------------------------------------------------------
-- Runtime config store (immutable snapshot)
-- ---------------------------------------------------------------------------
local config_store_raw = {}
local config_store = make_readonly(config_store_raw)
local config_keys = {}
if _M.schema and _M.schema.fields then
    for k in pairs(_M.schema.fields) do
        config_keys[k] = true
    end
end
config_keys.version = true
config_keys.admin = true

local config_mt = {
    __index = function(t, k)
        return config_store[k]
    end,
    __newindex = function(t, k, v)
        if not config_keys[k] then
            rawset(t, k, v)
            return
        end
        error("config is readonly, use config.save()")
    end
}
setmetatable(_M, config_mt)

-- Internal helper to atomically swap the config snapshot
local function set_config_store(new_raw)
    config_store_raw = new_raw
    config_store = make_readonly(config_store_raw)
end

_M.local_hash = nil
_M.config_path = nil

-- ---------------------------------------------------------------------------
-- Path helpers
-- ---------------------------------------------------------------------------
function _M.resolve_path()
    if _M.config_path then
        return _M.config_path
    end
    local script_path = debug.getinfo(1, "S").source:sub(2)
    _M.config_path = script_path:match("(.+/)core/config%.lua$")
    if not _M.config_path then
        _M.config_path = "/opt/verynginx/verynginx/"
    end
    return _M.config_path
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
-- Known actions from action registry
-- ---------------------------------------------------------------------------
local function get_known_actions()
    local ok, action_init = pcall(require, "action.init")
    if not ok or not action_init then
        return {"accept", "block", "redirect", "rewrite", "response", "proxy", "static"}
    end
    local actions = {}
    for name, _ in pairs(action_init.action_handlers or {}) do
        actions[name] = true
    end
    -- also include aliases mapped via __index metamethod
    return actions
end

-- ---------------------------------------------------------------------------
-- Validate a single rule for reference integrity
-- ---------------------------------------------------------------------------
local function validate_rule(rule, rule_idx, rule_group, config)
    -- Check action is known
    local ok_action, action_init = pcall(require, "action.init")
    if ok_action and action_init then
        local handler = action_init.get and action_init.get(rule.action)
        if not handler then
            return false, string.format("rule.%s[%d]: unknown action '%s'", rule_group, rule_idx, tostring(rule.action))
        end
    end

    -- Check matcher reference exists
    if rule.matcher then
        if type(rule.matcher) == "string" then
            if not config.matcher or not config.matcher[rule.matcher] then
                return false, string.format("rule.%s[%d]: matcher '%s' not found in config.matcher", rule_group, rule_idx, rule.matcher)
            end
        elseif type(rule.matcher) == "table" then
            -- inline matcher: check on_body_error values in Args conditions
            for cond_type, cond in pairs(rule.matcher) do
                if cond_type == "Args" and cond.on_body_error then
                    if cond.on_body_error ~= "match" and cond.on_body_error ~= "skip" and cond.on_body_error ~= "fail_closed" then
                        return false, string.format("rule.%s[%d]: on_body_error must be 'match', 'skip', or 'fail_closed', got '%s'",
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
        for group_name, rules in pairs(compiled.rule) do
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
                return false, string.format("admin[%d]: password must not be stored as password_hash directly, use password_hash.verify()", i)
            end
            if a.password and not a.password_hash then
                return false, string.format("admin[%d]: password must be stored as password_hash", i)
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
    local file, err = io.open(path, "r")
    if not file then
        ngx.log(ngx.WARN, "config file not found at ", path, ", using defaults")
        return false
    end

    local data = file:read("*all")
    file:close()

    local config = json.decode(data)
    if not config then
        ngx.log(ngx.ERR, "config.json decode error")
        return false
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
    local data = f_src:read("*all")
    f_dst:write(data)
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
    local lock_ttl = (config and config.config_save_lock_ttl) or 60
    local lock_token = random.bytes(16)

    if shared then
        local locked = shared:add(lock_key, lock_token, lock_ttl)
        if not locked then
            return false, "config save is already running"
        end
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
    return json.encode(config_store)
end

return _M