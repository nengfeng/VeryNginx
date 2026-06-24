-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : config management - load/save/hot-reload/rollback/validate

local _M = {}
local dkjson = require "dkjson"
local json = require "json"
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
-- Runtime config store (immutable snapshot)
-- ---------------------------------------------------------------------------
local config_store = table.immutable and table.immutable({}) or {}
local config_mt = {
    __index = function(t, k)
        return config_store[k]
    end,
    __newindex = function(t, k, v)
        error("config is readonly, use config.save()")
    end
}
setmetatable(_M, config_mt)

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
    return _M.resolve_path():match("(.+/)core/") or "/opt/verynginx/verynginx/"
end

-- ---------------------------------------------------------------------------
-- Config file paths
-- ---------------------------------------------------------------------------
local function config_json_path()
    return home_path() .. "configs/config.json"
end

-- ---------------------------------------------------------------------------
-- Deep table copy
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
-- Compile runtime snapshot (placeholder for Phase 2+ enhancements)
-- ---------------------------------------------------------------------------
local function compile_runtime_snapshot(config)
    -- Phase 2 will add: pre-compile regex, validate matcher/action/upstream refs
    return config
end

-- ---------------------------------------------------------------------------
-- Validate config schema and reference integrity
-- Will be enhanced in Phase 2 with matcher/action/upstream reference checks
-- ---------------------------------------------------------------------------
local function validate_config(config)
    if type(config) ~= "table" then
        return false, "config must be a table"
    end
    if config.version and config.version ~= _M.schema.version then
        return false, "unexpected config version: " .. tostring(config.version)
    end
    -- admin password_hash check: reject plaintext passwords
    if config.admin then
        for _, a in ipairs(config.admin) do
            if a.password and not a.password_hash then
                return false, "admin password must be stored as password_hash"
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
    config_store = compiled
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
    local p = io.popen('ls -1t "' .. backup_dir .. '" 2>/dev/null')
    if not p then
        return
    end
    local files = {}
    for f in p:lines() do
        if f:match("^config%.") then
            table.insert(files, f)
        end
    end
    p:close()
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
    local encoded = dkjson.encode(normalized, { indent = true })
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
    config_store = compiled
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
    return dkjson.encode(config_store)
end

return _M