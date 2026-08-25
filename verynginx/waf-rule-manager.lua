-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-28
-- @Author  : VeryNginx v2
-- @Disc    : WAF rule manager - CRUD, validation, caching, stats, rate limiting
--
-- Provides a hot-reloadable rule management system for VeryNginx v2.
-- Rules are stored in:
--   Layer 1: shared dict (chunked, for runtime reads)
--   Layer 2: JSON file (persistent, for durability)

local _M = {}
local cjson_ok = pcall(require, "cjson")
local json = cjson_ok and require("cjson") or require("dkjson")
local config = require("core.config")
local matcher = require("matcher.init")

-- cjson.encode takes exactly 1 arg; dkjson accepts {indent=true} as 2nd arg
local function jencode(data, opts)
    if opts and not cjson_ok then
        return json.encode(data, opts)
    end
    return json.encode(data)
end


-- ---------------------------------------------------------------------------
-- Shared dict key prefixes
-- ---------------------------------------------------------------------------
local CACHE_PREFIX  = "waf_rules:chunk:"
local META_KEY      = "waf_rules:meta"
local VERSION_KEY   = "waf_rules_version"
local STATS_PREFIX  = "waf_rule_stats:"
local STATS_INDEX_KEY = "waf_rule_stats:index"
local RATE_PREFIX   = "waf_rate_limit:"
local HIT_PREFIX    = "waf_hit:"

-- Chunk size: each chunk stores at most this many rules to stay under the
-- 1 MB shared-dict value-size limit.  100 rules × ~8KB/rule = ~800 KB.
local CHUNK_SIZE = 100

-- ---------------------------------------------------------------------------
-- Utility: chunk / unchunk
-- ---------------------------------------------------------------------------

local function chunk_rules(rules)
    local chunks = {}
    for i, rule in ipairs(rules) do
        local idx = math.ceil(i / CHUNK_SIZE)
        if not chunks[idx] then
            chunks[idx] = { rules = {}, count = 0 }
        end
        table.insert(chunks[idx].rules, rule)
        chunks[idx].count = chunks[idx].count + 1
    end
    return chunks
end

local function unchunk_rules(chunks)
    local rules = {}
    local keys = {}
    for k in pairs(chunks) do
        keys[#keys + 1] = tonumber(k)
    end
    table.sort(keys)
    for _, k in ipairs(keys) do
        local chunk = chunks[tostring(k)]
        for _, rule in ipairs(chunk.rules) do
            rules[#rules + 1] = rule
        end
    end
    return rules
end

--- Drop corrupt entries from a decoded rules array.
-- A hand-edited/imported rules file can contain [null] holes; cjson decodes
-- those to cjson.null (lightuserdata), which is NOT nil — ipairs keeps going
-- and the sentinel flows into the API response ("r.id" crash on the dashboard)
-- AND into per-request rule evaluation. Only real tables survive here.
function _M.sanitize_rule_list(rules)
    if type(rules) ~= "table" then return {} end
    local out, dropped = {}, 0
    for _, r in ipairs(rules) do
        if type(r) == "table" then
            out[#out + 1] = r
        else
            dropped = dropped + 1
        end
    end
    if dropped > 0 then
        pcall(function()
            ngx.log(ngx.WARN, "waf-rule-manager: dropped ", dropped,
                " corrupt (non-table) rule entries")
        end)
    end
    return out
end

-- ---------------------------------------------------------------------------
-- Utility: deep copy (recursive, depth limit = 100)
-- ---------------------------------------------------------------------------
local function deep_copy(t, depth)
    depth = depth or 0
    if depth > 100 then return {} end
    if type(t) ~= "table" then return t end
    local copy = {}
    for k, v in pairs(t) do
        copy[k] = deep_copy(v, depth + 1)
    end
    return copy
end

-- ---------------------------------------------------------------------------
-- K: WAF rules key constants
-- ---------------------------------------------------------------------------
_M.SEVERITY_LEVELS = { critical = 1, high = 2, medium = 3, low = 4 }
_M.ACTIONS         = { block = true, accept = true, log = true, challenge = true }
_M.CATEGORIES      = {
    sqli = true, xss = true, rce = true, lfi = true, rfi = true,
    path_traversal = true, scanner = true, bot = true, brute = true,
    spam = true, custom = true
}

-- ---------------------------------------------------------------------------
-- Writable storage directory (resolved lazily, cached, fallback to /tmp)
-- Uses a shared-dict key so all workers agree on the same path.
-- ---------------------------------------------------------------------------
local _writable_base
local WRIATBLE_DIR_KEY = "waf_rules:writable_dir"

local function ensure_writable_dir()
    if _writable_base then return _writable_base end

    -- Check if another worker already resolved the path
    local shared = ngx.shared.vn_config
    if shared then
        local cached = shared:get(WRIATBLE_DIR_KEY)
        if cached and cached ~= "" then
            _writable_base = cached
            os.execute("mkdir -p '" .. cached .. "' 2>/dev/null")
            return _writable_base
        end
    end

    local primary = config.resolve_path() .. "configs/"
    os.execute("mkdir -p '" .. primary .. "' 2>/dev/null")
    local f = io.open(primary .. ".waf_write_test", "w")
    if f then f:close(); os.remove(primary .. ".waf_write_test") _writable_base = primary
    else
        local fallback = "/tmp/verynginx/configs/"
        os.execute("mkdir -p '" .. fallback .. "' 2>/dev/null")
        _writable_base = fallback
    end

    if shared then
        shared:add(WRIATBLE_DIR_KEY, _writable_base)
    end
    return _writable_base
end

local function rules_path()
    return ensure_writable_dir() .. "waf-rules.json"
end

local function history_path()
    return ensure_writable_dir() .. "waf-rules-history.json"
end

local function backup_prefix()
    return ensure_writable_dir() .. "waf-rules-backup-"
end

-- ---------------------------------------------------------------------------
-- load_rules  — load from shared dict chunks, fallback to file
-- ---------------------------------------------------------------------------
-- Returns { version, timestamp, rules = [...] } or nil.
function _M.load_rules()
    local shared = ngx.shared.vn_config
    if shared then
        local meta_json = shared:get(META_KEY)
        if meta_json then
            local ok, meta = pcall(json.decode, meta_json)
            if ok and meta and meta.chunk_count and meta.chunk_count > 0 then
                local chunks = {}
                local complete = true
                for i = 1, meta.chunk_count do
                    local chunk_json = shared:get(CACHE_PREFIX .. i)
                    if chunk_json then
                        local ok2, chunk = pcall(json.decode, chunk_json)
                        if ok2 and chunk then
                            chunks[tostring(i)] = chunk
                        else
                            complete = false
                        end
                    else
                        complete = false
                    end
                end
                -- Only trust the cached rules if every chunk is present and
                -- decodable. A missing/a corrupt chunk otherwise yields a
                -- silently truncated rule set.
                if complete and next(chunks) then
                    return {
                        version   = meta.version,
                        timestamp = meta.timestamp,
                        rules     = _M.sanitize_rule_list(unchunk_rules(chunks))
                    }
                end
                if not complete then
                    ngx.log(ngx.WARN, "waf-rule-manager: cached rules incomplete "
                        .. "(expected ", tostring(meta.chunk_count), " chunks), "
                        .. "falling back to disk")
                end
            end
        end
    end
    return _M.load_from_file()
end

-- ---------------------------------------------------------------------------
-- load_from_file  — load rules from JSON file
-- ---------------------------------------------------------------------------
-- Returns { version, timestamp, rules = [...] } or nil.
function _M.load_from_file()
    local path = rules_path()
    local f = io.open(path, "r")
    if not f then
        ngx.log(ngx.WARN, "waf-rule-manager: rules file not found at ", path)
        return nil
    end
    local content = f:read("*all")
    f:close()
    if not content or content == "" then return nil end
    local ok, data = pcall(json.decode, content)
    if not ok or not data then return nil end
    if type(data) == "table" and data.rules then
        return {
            version   = data.version or 1,
            timestamp = data.timestamp,
            rules     = _M.sanitize_rule_list(data.rules)
        }
    end
    -- Legacy bare array format
    if type(data) == "table" then
        return { version = 1, timestamp = nil, rules = data }
    end
    return nil
end

-- ---------------------------------------------------------------------------
-- save_rules  — atomic file write + chunk cache update + backup + history
-- ---------------------------------------------------------------------------
function _M.save_rules(rules, action)
    if type(rules) ~= "table" then
        return false, "rules must be a table"
    end

    -- Serialize the whole multi-step save (backup → file rename → chunk
    -- writes → meta → version bump) across workers. Without this, two
    -- interleaved saves could commit meta from one version over chunks of
    -- another — load_rules then serves a hybrid rule set cached against the
    -- newest version marker. Token-checked so an expired lock can't be
    -- released by its previous owner.
    local locks = ngx.shared.vn_locks
    local lock_key = "waf_rules_save_lock"
    local lock_token = require("core.random").hex(8)
    local locked = false
    if locks then
        for _ = 1, 500 do
            if locks:add(lock_key, lock_token, 30) then locked = true; break end
            ngx.sleep(0.002)
        end
        if not locked then
            return false, "waf rules save lock busy"
        end
    end

    local ok, r1, r2 = pcall(_M._save_rules_unlocked, rules, action)

    if locked and locks then
        -- release only if we still own it (TTL may have expired and been
        -- taken over — in that case the new owner is mid-save; our data is
        -- already fully written by the pcall above either way)
        if locks:get(lock_key) == lock_token then
            locks:delete(lock_key)
        end
    end
    -- pcall error OR the unlocked body's own (false, err) returns
    if not ok then
        return false, tostring(r1)
    end
    if r1 == false then
        return false, tostring(r2 or "save failed")
    end
    return true
end

function _M._save_rules_unlocked(rules, action)
    local shared = ngx.shared.vn_config
    local current_version
    if shared then
        current_version = shared:incr("waf_rules_save_version", 1, 0)
    else
        current_version = 1
    end

    local timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ")
    local data = {
        version   = current_version,
        timestamp = timestamp,
        rules     = rules
    }

    -- 1. Backup old file
    local path = rules_path()
    local old_f = io.open(path, "r")
    if old_f then
        local old_data = old_f:read("*all")
        old_f:close()
        if old_data and #old_data > 0 then
            local bk_path = backup_prefix() .. string.format("%.0f", ngx.now() * 1000) .. ".json"
            local bf = io.open(bk_path, "w")
            if bf then
                bf:write(old_data)
                bf:close()
            end
        end
    end

    -- 2. Prune old backups (keep newest 10)
    local function prune_backups()
        local dir = ensure_writable_dir()
        local backups = {}
        local ok, lfs = pcall(require, "lfs")
        if ok then
            for f in lfs.dir(dir) do
                if f:match("^waf%-rules%-backup%-") then
                    backups[#backups + 1] = dir .. f
                end
            end
        else
            local fh = io.popen('ls -1t "' .. dir .. '"waf-rules-backup-* 2>/dev/null', "r")
            if not fh then return end
            for line in fh:lines() do
                backups[#backups + 1] = line
            end
            fh:close()
        end
        table.sort(backups, function(a, b) return a > b end)
        for i = 11, #backups do
            os.remove(backups[i])
        end
    end
    prune_backups()

    -- 3. Atomic write
    local tmp_path = path .. ".tmp"
    local f = io.open(tmp_path, "w")
    if not f then return false, "cannot open temp file" end
    local encoded, err = jencode(data, { indent = true })
    if not encoded then
        f:close()
        os.remove(tmp_path)
        return false, "json encode failed: " .. tostring(err)
    end
    f:write(encoded)
    f:close()
    local renamed, rerr = os.rename(tmp_path, path)
    if not renamed then
        return false, "rename failed: " .. tostring(rerr)
    end

    -- 4. Update shared dict chunks
    if shared then
        local old_meta_json = shared:get(META_KEY)
        local old_chunk_count = 0
        if old_meta_json then
            local ok2, old_meta = pcall(json.decode, old_meta_json)
            if ok2 and old_meta then
                old_chunk_count = old_meta.chunk_count or 0
            end
        end

        local chunks = chunk_rules(rules)
        for idx, chunk in pairs(chunks) do
            shared:set(CACHE_PREFIX .. idx, json.encode(chunk))
        end

        -- Clean up stale chunk keys
        if old_chunk_count > #chunks then
            for i = #chunks + 1, old_chunk_count do
                shared:delete(CACHE_PREFIX .. i)
            end
        end

        local meta = {
            version     = current_version,
            timestamp   = timestamp,
            chunk_count = #chunks,
            rule_count  = #rules,
            updated_at  = ngx.time()
        }
        shared:set(META_KEY, json.encode(meta))
        shared:set(VERSION_KEY, tostring(current_version))
    end

    -- 5. Record history
    _M.record_history(rules, current_version, timestamp, action)

    return true
end

--- _save_rules_through_config — save rules via approval flow (used by confirm endpoint)
function _M._save_rules_through_config(rules)
    return _M.save_rules(rules, "confirm_pending")
end

-- ---------------------------------------------------------------------------
-- record_history  — append a snapshot to the history file
-- ---------------------------------------------------------------------------
function _M.record_history(rules, version, timestamp, action)
    -- Read existing history
    local path = history_path()
    local history = {}
    local f = io.open(path, "r")
    if f then
        local content = f:read("*all")
        f:close()
        if content and #content > 0 then
            local ok, existing = pcall(json.decode, content)
            if ok and type(existing) == "table" then
                history = existing
            end
        end
    end

    -- Append this version
    history[#history + 1] = {
        version   = version,
        timestamp = timestamp,
        action    = action or "update",
        rule_count = #rules,
        rule_data = deep_copy(rules)
    }

    -- Keep newest 100 entries
    if #history > 100 then
        local recent = {}
        for i = #history - 99, #history do
            recent[#recent + 1] = history[i]
        end
        history = recent
    end

    -- Write atomically
    local tmp_path = path .. ".tmp"
    local wf = io.open(tmp_path, "w")
    if wf then
        local encoded = jencode(history, { indent = true })
        if encoded then
            wf:write(encoded)
        end
        wf:close()
        os.rename(tmp_path, path)
    end
end

-- ---------------------------------------------------------------------------
-- get_history  — return recent history entries
-- ---------------------------------------------------------------------------
function _M.get_history(limit)
    local path = history_path()
    local f = io.open(path, "r")
    if not f then return {} end
    local content = f:read("*all")
    f:close()
    if not content or #content == 0 then return {} end
    local ok, history = pcall(json.decode, content)
    if not ok or type(history) ~= "table" then return {} end
    if limit and #history > limit then
        local recent = {}
        for i = #history - limit + 1, #history do
            recent[#recent + 1] = history[i]
        end
        return recent
    end
    return history
end

-- ---------------------------------------------------------------------------
-- generate_id  — create a unique rule ID
-- ---------------------------------------------------------------------------
function _M.generate_id(name)
    local prefix = (name or "rule"):lower():match("^(%w+)") or "rule"
    if #prefix == 0 then prefix = "rule" end
    local ts = ngx.time()
    local random_hex = require("core.random").hex(4)
    return string.format("%s_%d_%s", prefix, ts, random_hex)
end

-- ---------------------------------------------------------------------------
-- merge_rule  — merge updates into rule, preserving runtime stats
-- ---------------------------------------------------------------------------
function _M.merge_rule(rule, updates)
    local merged = {}
    for k, v in pairs(rule) do
        merged[k] = v
    end
    for k, v in pairs(updates) do
        if k ~= "hit_count" and k ~= "last_triggered" and k ~= "last_matched_uri" then
            merged[k] = v
        end
    end
    -- Restore runtime stats from original
    merged.hit_count        = rule.hit_count
    merged.last_triggered   = rule.last_triggered
    merged.last_matched_uri = rule.last_matched_uri
    return merged
end

-- ---------------------------------------------------------------------------
-- validate_rule  — comprehensive field validation
-- ---------------------------------------------------------------------------
function _M.validate_rule(rule)
    if type(rule) ~= "table" then
        return false, "rule must be a table"
    end
    -- Client-supplied ids flow into dict keys, pipe-framed hit records and the
    -- newline-delimited stats index: constrain to safe charset/length or a
    -- "|" in an id corrupts stats attribution and "\n" forges index entries.
    if rule.id ~= nil then
        -- (Lua patterns have no {n,m} quantifier — check length separately)
        if type(rule.id) ~= "string" or #rule.id == 0 or #rule.id > 64
            or not rule.id:match("^[%w_-]+$") then
            return false, "id must be 1-64 chars of [A-Za-z0-9_-]"
        end
    end
    if not rule.name or type(rule.name) ~= "string" or #rule.name == 0 then
        return false, "name is required"
    end
    if #rule.name > 100 then
        return false, "name must be at most 100 characters"
    end
    if not rule.category or not _M.CATEGORIES[rule.category] then
        return false, "invalid category: " .. tostring(rule.category)
    end
    if not rule.severity or not _M.SEVERITY_LEVELS[rule.severity] then
        return false, "invalid severity: " .. tostring(rule.severity)
    end
    if not rule.action or not _M.ACTIONS[rule.action] then
        return false, "invalid action: " .. tostring(rule.action)
    end
    if rule.matcher == nil then
        return false, "matcher is required"
    end
    if type(rule.matcher) == "string" then
        -- Reference to a named matcher in config
        local cfg = require("core.config")
        if not cfg.matcher or not cfg.matcher[rule.matcher] then
            return false, "matcher '" .. rule.matcher .. "' not found in config.matcher"
        end
    elseif type(rule.matcher) ~= "table" then
        return false, "matcher must be a string reference or inline table"
    end
    -- Validate IP matcher values: the matcher engine (matcher/ip.lua) only does
    -- plain string equality ("=") or regex ("≈") — it has no CIDR support. A
    -- value like "10.0.0.0/8" would validate as an IP here (once stripped) but
    -- silently never match any request. Reject malformed IPs and any CIDR.
    -- Check both inline matchers and string-referenced matchers (config.matcher).
    do
        local helpers = require "api.helpers"
        local function check_ip_condition(cond)
            if type(cond) == "table" and type(cond.value) == "string" and cond.value ~= "" then
                local addr = cond.value
                if addr:find("/") then
                    return false, "IP matcher does not support CIDR notation: " .. addr
                end
                if not helpers.is_valid_ip(addr) then
                    return false, "invalid IP in matcher: " .. addr
                end
            end
            return true
        end
        local matcher_def = rule.matcher
        if type(matcher_def) == "string" then
            local cfg = require("core.config")
            matcher_def = cfg.matcher and cfg.matcher[matcher_def]
        end
        if type(matcher_def) == "table" and type(matcher_def.IP) == "table" then
            local ip_ok, ip_err = check_ip_condition(matcher_def.IP)
            if not ip_ok then
                return false, ip_err
            end
        end
        -- Compile-check every regex matcher value ("≈"/"!≈"). An invalid
        -- pattern stored here used to turn each evaluated request into a 503
        -- (compare.match's compile failure path). Reject at save time instead.
        -- Skipped where ngx.re.compile is absent (minimal unit-test rigs).
        if type(matcher_def) == "table"
            and type(ngx.re) == "table" and type(ngx.re.compile) == "function" then
            for cond_key, cond in pairs(matcher_def) do
                if type(cond) == "table" and type(cond.operator) == "string"
                    and (cond.operator == "≈" or cond.operator == "!≈")
                    and type(cond.value) == "string" and cond.value ~= "" then
                    local cok, cres = pcall(ngx.re.compile, cond.value, "isjo")
                    if not cok or not cres then
                        return false, "invalid regex in matcher." .. tostring(cond_key) .. ": " .. tostring(cond.value)
                    end
                end
            end
        end
    end
    if rule.code ~= nil then
        if type(rule.code) ~= "number" or rule.code < 200 or rule.code > 599 then
            return false, "code must be a valid HTTP status code (200-599)"
        end
    end
    if rule.response and type(rule.response) == "string" then
        local cfg = require("core.config")
        if not cfg.response or not cfg.response[rule.response] then
            return false, "response template '" .. rule.response .. "' not found"
        end
    end
    if rule.rate_limit and rule.rate_limit.enable then
        local max_hits = rule.rate_limit.max_hits
        local window  = rule.rate_limit.window
        if type(max_hits) ~= "number" or max_hits < 1 or max_hits > 10000 then
            return false, "rate_limit.max_hits must be between 1 and 10000"
        end
        if type(window) ~= "number" or window < 1 or window > 3600 then
            return false, "rate_limit.window must be between 1 and 3600 seconds"
        end
        if rule.rate_limit.action and rule.rate_limit.action ~= "log" and rule.rate_limit.action ~= "block" then
            return false, "rate_limit.action must be 'log' or 'block'"
        end
    end
    return true
end

-- ---------------------------------------------------------------------------
-- create_rule  — create a new rule with auto-generated ID and metadata
-- ---------------------------------------------------------------------------
function _M.create_rule(rule)
    local ok, err = _M.validate_rule(rule)
    if not ok then return false, err end

    local id = rule.id or _M.generate_id(rule.name)

    -- Check for duplicate ID
    local rules_obj = _M.load_rules()
    local rules = (rules_obj and rules_obj.rules) or {}
    for _, r in ipairs(rules) do
        if r.id == id then
            return false, "rule id already exists: " .. id
        end
    end

    local now = os.date("!%Y-%m-%dT%H:%M:%SZ")
    local new_rule = deep_copy(rule)
    new_rule.id           = id
    new_rule.enable       = (rule.enable ~= false)
    new_rule.priority     = rule.priority or 100
    new_rule.created_at   = now
    new_rule.updated_at   = now
    new_rule.created_by   = "admin"
    new_rule.version      = 1
    new_rule.hit_count    = 0

    rules[#rules + 1] = new_rule
    local save_ok, save_err = _M.save_rules(rules, "create")
    if not save_ok then return false, save_err end
    return true, new_rule
end

-- ---------------------------------------------------------------------------
-- update_rule  — update an existing rule
-- ---------------------------------------------------------------------------
function _M.update_rule(rule_id, updates)
    local rules_obj = _M.load_rules()
    local rules = (rules_obj and rules_obj.rules) or {}
    for i, r in ipairs(rules) do
        if r.id == rule_id then
            updates.updated_at = os.date("!%Y-%m-%dT%H:%M:%SZ")
            updates.version    = (r.version or 1) + 1

            local merged = _M.merge_rule(r, updates)
            local ok_v, err_v = _M.validate_rule(merged)
            if not ok_v then return false, err_v end
            rules[i] = merged
            local save_ok, save_err = _M.save_rules(rules, "update")
            if not save_ok then return false, save_err end
            return true, merged
        end
    end
    return false, "rule not found: " .. rule_id
end

-- ---------------------------------------------------------------------------
-- delete_rule  — delete a rule
-- ---------------------------------------------------------------------------
function _M.delete_rule(rule_id)
    local rules_obj = _M.load_rules()
    local rules = (rules_obj and rules_obj.rules) or {}
    for i, r in ipairs(rules) do
        if r.id == rule_id then
            table.remove(rules, i)
            return _M.save_rules(rules, "delete")
        end
    end
    return false, "rule not found: " .. rule_id
end

-- ---------------------------------------------------------------------------
-- create_mock_context  — create a fake request context for rule testing
-- ---------------------------------------------------------------------------
function _M.create_mock_context(case)
    case = case or {}
    local ctx = {
        request = {
            uri          = case.uri or "/",
            method       = case.method or "GET",
            remote_addr  = case.ip or "127.0.0.1",
            host         = case.host or "localhost",
            user_agent   = case.ua or "Mozilla/5.0",
            referer      = case.referer or "",
            scheme       = "http",
            _body_args   = nil,
            _body_read   = false,
            _body_error  = nil,
        },
        action_result    = nil,
        data             = {},
        match_cache      = {},
        match_cache_size = 0,
    }

    function ctx:get_uri_args()
        local args = {}
        local qs = self.request.uri:match("%?(.*)")
        if qs then
            for k, v in qs:gmatch("([^&=]+)=([^&]*)") do
                args[k] = v
            end
        end
        return args
    end

    function ctx:get_body_args()
        return self.request._body_args or {}
    end

    function ctx:set_action(action, action_data)
        self.action_result = { type = action, data = action_data }
    end

    function ctx:has_decision()
        return self.action_result ~= nil
    end

    function ctx:clear_action()
        self.action_result = nil
    end

    function ctx:set_data(k, v)
        self.data[k] = v
    end

    function ctx:get_data(k)
        return self.data[k]
    end

    return ctx
end

-- ---------------------------------------------------------------------------
-- test_rule  — test a rule against a set of test cases
-- ---------------------------------------------------------------------------
function _M.test_rule(rule, test_cases)
    local results = {}
    if type(test_cases) ~= "table" then return results end
    if not rule or not rule.matcher then
        for _, case in ipairs(test_cases) do
            results[#results + 1] = {
                name    = case.name,
                uri     = case.uri,
                matched = false,
                passed  = false
            }
        end
        return results
    end
    for _, case in ipairs(test_cases) do
        local ctx = _M.create_mock_context(case)
        local matched = matcher.test(rule.matcher, ctx)
        results[#results + 1] = {
            name    = case.name,
            uri     = case.uri,
            matched = matched,
            passed  = (matched == case.expected)
        }
    end
    return results
end

-- ---------------------------------------------------------------------------
-- check_rate_limit  — sliding-window rate limit via shared dict incr
-- ---------------------------------------------------------------------------
function _M.check_rate_limit(rule_id, rule)
    if not rule.rate_limit or not rule.rate_limit.enable then
        return true
    end
    local shared = ngx.shared.vn_config
    if not shared then return true end

    local window = rule.rate_limit.window or 60
    local slot = math.floor(ngx.time() / window)
    local key = RATE_PREFIX .. rule_id .. ":" .. tostring(slot)
    local count = shared:incr(key, 1, 0, window)
    if not count then
        -- incr failure indicates the key was created with TTL but
        -- immediately expired in a race — treat as not limited
        return true
    end
    if count > (rule.rate_limit.max_hits or 10) then
        return false
    end
    return true
end

-- ---------------------------------------------------------------------------
-- Capture request detail once per request, cache in ngx.ctx for reuse.
-- ---------------------------------------------------------------------------
local function capture_request_detail()
    if ngx.ctx and ngx.ctx._waf_req_detail then
        return ngx.ctx._waf_req_detail
    end
    local detail = {
        headers = {},
        body_snippet = "",
    }
    -- Capture headers
    local headers = ngx.req.get_headers()
    for k, v in pairs(headers) do
        if type(v) == "string" and #v < 500 then
            detail.headers[k] = v
        end
    end
    -- Capture body snippet (first 1KB)
    pcall(function()
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        if body and #body > 0 then
            detail.body_snippet = body:sub(1, 1024)
        end
    end)
    -- Capture TLS/JA3 fingerprint if available
    pcall(function()
        local ja3_mod = require "core.ja3"
        local ja3 = ja3_mod.get_fingerprint()
        if ja3 then
            detail.ja3_fingerprint = ja3
        end
    end)
    if ngx.ctx then
        ngx.ctx._waf_req_detail = detail
    end
    return detail
end

-- ---------------------------------------------------------------------------
-- record_hit  — push a hit event into the async buffer (O(1), non-blocking)
-- ---------------------------------------------------------------------------
function _M.record_hit(rule_id, ctx, action)
    local shared = ngx.shared.vn_config

    -- Drop hit if buffer is too large (prevents unbounded growth when
    -- flush cannot keep pace, e.g. burst >5000 hits per 30s cycle)
    local head = tonumber(shared:get(HIT_PREFIX .. "head") or 0)
    local tail = tonumber(shared:get(HIT_PREFIX .. "tail") or 0)
    if tail - head >= 5000 then
        return
    end

    local hit_action = action or "log"
    local hit_data = table.concat({
        rule_id,
        hit_action,
        tostring(ngx.time()),
        ctx.request.uri or "",
        ctx.request.remote_addr or "",
        ctx.request.method or "GET"
    }, "|")

    local idx = shared:incr(HIT_PREFIX .. "tail", 1, 0)
    -- TTL: a consumer racing this write can advance head past the slot,
    -- leaving it unconsumed forever — let strays self-expire instead of
    -- leaking vn_config under sustained load.
    shared:set(HIT_PREFIX .. tostring(idx), hit_data, 600)
    -- Independent per-day counter so "today's hits" can't be inflated by a
    -- rule's all-time total (stats previously added hit_count when
    -- last_triggered fell inside today).
    pcall(function()
        local day = os.date("!%Y%m%d")
        shared:incr("waf_rule_stats:" .. tostring(rule_id) .. ":today:" .. day, 1, 0, 172800)
        if hit_action == "challenge" then
            -- Per-day challenge count: numerator of the analytics pass-rate
            -- (:cpass:) is also per-day; a lifetime denominator made the rate
            -- decay toward 0% over time.
            shared:incr("waf_rule_stats:" .. tostring(rule_id) .. ":chal:" .. day, 1, 0, 172800)
        end
    end)

    -- Ring buffer for recent hits display (keep last 100)
    local ring_idx = (shared:incr("waf_recent_hits:idx", 1, 0) - 1) % 100 + 1

    -- Build detail reusing cached request-level data (headers/body/ja3)
    local req_detail = capture_request_detail()
    local detail = {
        rule_id = rule_id,
        action = hit_action,
        timestamp = ngx.time(),
        uri = ctx.request.uri or "",
        ip = ctx.request.remote_addr or "",
        method = ctx.request.method or "GET",
        user_agent = ctx.request.user_agent or "",
        query_string = ngx.var.query_string or "",
        headers = req_detail.headers,
        body_snippet = req_detail.body_snippet,
        ja3_fingerprint = req_detail.ja3_fingerprint,
    }
    shared:set("waf_recent_hits:data:" .. ring_idx, json.encode(detail))
end

-- ---------------------------------------------------------------------------
-- get_recent_hits  — read the ring buffer of recent WAF hits
-- ---------------------------------------------------------------------------
function _M.get_recent_hits(limit)
    local shared = ngx.shared.vn_config
    if not shared then return {} end
    local tail = tonumber(shared:get("waf_recent_hits:idx") or 0)
    if not tail or tail == 0 then return {} end
    limit = limit or 50
    if limit > 100 then limit = 100 end
    local hits = {}
    for i = 0, limit - 1 do
        local idx = ((tail - 1 - i) % 100) + 1
        local data = shared:get("waf_recent_hits:data:" .. idx)
        if not data then break end
        local ok, detail = pcall(json.decode, data)
        if ok and detail then
            hits[#hits + 1] = {
                rule_id = detail.rule_id or "",
                time = detail.timestamp or 0,
                uri = detail.uri or "",
                ip = detail.ip or "",
                method = detail.method or "GET",
                ring_idx = idx,
            }
        end
    end
    return hits
end

-- ---------------------------------------------------------------------------
-- persist_recent_hits  — write the ring buffer to disk so it survives
--                        nginx restart.  Called by ngx.timer.every.
-- ---------------------------------------------------------------------------
function _M.persist_recent_hits()
    local shared = ngx.shared.vn_config
    if not shared then return end
    local entries = {}
    for ri = 1, 100 do
        local data = shared:get("waf_recent_hits:data:" .. ri)
        if data then entries[#entries + 1] = data end
    end
    if #entries == 0 then return end
    local path = ensure_writable_dir() .. "waf-recent-hits.json"
    local tmp_path = path .. ".tmp"
    local f = io.open(tmp_path, "w")
    if not f then return end
    local encoded, err = json.encode(entries)
    if not encoded then
        ngx.log(ngx.WARN, "waf-rule-manager: persist encode failed: ", tostring(err))
        f:close()
        os.remove(tmp_path)
        return
    end
    f:write(encoded)
    f:close()
    os.rename(tmp_path, path)
end

-- ---------------------------------------------------------------------------
-- restore_recent_hits  — re-populate the ring buffer from disk after a
--                        restart.  Only the first worker actually loads.
-- ---------------------------------------------------------------------------
function _M.restore_recent_hits()
    local shared = ngx.shared.vn_config
    if not shared then return end

    -- Only restore once across all workers
    if not shared:add("waf_recent_hits:restored", 1) then return end

    local path = ensure_writable_dir() .. "waf-recent-hits.json"
    local f = io.open(path, "r")
    if not f then return end
    local content = f:read("*all")
    f:close()
    if not content or content == "" then return end
    local ok, entries = pcall(json.decode, content)
    if not ok or type(entries) ~= "table" then return end

    for _, data in ipairs(entries) do
        local ring_idx = (shared:incr("waf_recent_hits:idx", 1, 0) - 1) % 100 + 1
        shared:set("waf_recent_hits:data:" .. ring_idx, data)
    end
end

-- ---------------------------------------------------------------------------
-- flush_hit_stats  — consume the hit buffer and aggregate into persistent
--                    rule stats.  Called by ngx.timer.every.
-- ---------------------------------------------------------------------------
function _M.flush_hit_stats()
    local shared = ngx.shared.vn_config
    if not shared then return end

    local head = tonumber(shared:get(HIT_PREFIX .. "head") or 0)
    local tail = tonumber(shared:get(HIT_PREFIX .. "tail") or 0)
    if not tail or head >= tail then return end

    local max_process = math.min(tail - head, 5000)

    local stats_agg = {}
    for i = 1, max_process do
        local key = HIT_PREFIX .. tostring(head + i)
        local hit_data = shared:get(key)
        if hit_data then
            shared:delete(key)
            -- Format: rule_id|action|timestamp|uri|ip|method
            local rule_id, action, ts_str, rest = hit_data:match(
                "^([^|]*)|([^|]*)|([^|]*)|(.*)$")
            -- Parse uri from rest (URI may contain | so greedy from right)
            local uri = rest and rest:match("^(.-)|[^|]*|[^|]*$") or rest
            if rule_id and #rule_id > 0 then
                local ts = tonumber(ts_str)
                if not stats_agg[rule_id] then
                    stats_agg[rule_id] = { hit_count = 0, block_count = 0, challenge_count = 0,
                        last_triggered = 0, last_matched_uri = "" }
                end
                local agg = stats_agg[rule_id]
                agg.hit_count = agg.hit_count + 1
                if action == "block" then agg.block_count = (agg.block_count or 0) + 1 end
                if action == "challenge" then agg.challenge_count = (agg.challenge_count or 0) + 1 end
                if ts and ts > agg.last_triggered then
                    agg.last_triggered = ts
                    agg.last_matched_uri = uri or ""
                end
            end
        end
    end

    -- Advance head pointer
    shared:set(HIT_PREFIX .. "head", head + max_process)

    -- Merge aggregated stats into persistent stats
    for rule_id, agg in pairs(stats_agg) do
        local stats_key = STATS_PREFIX .. rule_id
        local existing_json = shared:get(stats_key)
        local existing = {}
        if existing_json then
            local ok, decoded = pcall(json.decode, existing_json)
            if ok and type(decoded) == "table" then
                existing = decoded
            end
        end

        -- Accumulate
        agg.hit_count = (existing.hit_count or 0) + agg.hit_count
        agg.block_count = (existing.block_count or 0) + (agg.block_count or 0)
        agg.challenge_count = (existing.challenge_count or 0) + (agg.challenge_count or 0)
        if agg.last_triggered < (existing.last_triggered or 0) then
            agg.last_triggered   = existing.last_triggered
            agg.last_matched_uri = existing.last_matched_uri or ""
        end

        shared:set(stats_key, json.encode(agg))
        -- Maintain index of rule stat keys for fast iteration (atomic with lock)
        local locks = ngx.shared.vn_locks
        if locks then
            local STATS_INDEX_LOCK_KEY = "waf_rule_stats:index_lock"
            local STATS_INDEX_LOCK_TTL = 5
            local STATS_INDEX_LOCK_SLEEP = 0.002
            local STATS_INDEX_LOCK_MAX_RETRIES = 500
            local token = require("core.random").bytes(8)
            local retries = 0
            while not locks:add(STATS_INDEX_LOCK_KEY, token, STATS_INDEX_LOCK_TTL) do
                retries = retries + 1
                if retries > STATS_INDEX_LOCK_MAX_RETRIES then
                    ngx.log(ngx.WARN, "waf-rule-manager: index lock unavailable after ",
                        STATS_INDEX_LOCK_MAX_RETRIES, " retries; index may miss key: ",
                        rule_id)
                    goto index_done
                end
                ngx.sleep(STATS_INDEX_LOCK_SLEEP)
            end
            -- Re-check under lock
            local idx_raw = shared:get(STATS_INDEX_KEY) or ""
            if not idx_raw:find("\n" .. rule_id .. "\n", 1, true) then
                shared:set(STATS_INDEX_KEY, idx_raw .. rule_id .. "\n", 0)
            end
            if locks:get(STATS_INDEX_LOCK_KEY) == token then
                locks:delete(STATS_INDEX_LOCK_KEY)
            end
            ::index_done::
        end
    end
end

-- ---------------------------------------------------------------------------
-- init_worker  — restore hits from disk, set up periodic timers
-- ---------------------------------------------------------------------------
function _M.init_worker()
    _M.restore_recent_hits()
    _M.restore_rule_stats()

    -- Only worker 0 runs periodic timers to avoid double counting / head races
    if ngx.worker.id() ~= 0 then return end

    local ok, err = ngx.timer.every(30, function()
        _M.flush_hit_stats()
        _M.persist_recent_hits()
        _M.persist_rule_stats()
    end)
    if not ok then
        ngx.log(ngx.ERR, "waf-rule-manager: failed to create timer: ", tostring(err))
    end
end

-- ---------------------------------------------------------------------------
-- persist_rule_stats  — save per-rule stats to disk so total/today hits
--                       survive nginx restart.  Called by ngx.timer.every.
-- Uses STATS_INDEX_KEY to avoid get_keys(0) 1024-key ceiling.
-- ---------------------------------------------------------------------------
function _M.persist_rule_stats()
    local shared = ngx.shared.vn_config
    if not shared then return end

    local idx_raw = shared:get(STATS_INDEX_KEY)
    if not idx_raw then return end

    local stats = {}
    for rule_id in idx_raw:gmatch("([^\n]+)") do
        if rule_id ~= "" then
            local raw = shared:get(STATS_PREFIX .. rule_id)
            if raw then
                local ok, decoded = pcall(json.decode, raw)
                if ok and type(decoded) == "table" then
                    stats[rule_id] = decoded
                end
            end
        end
    end
    if next(stats) == nil then return end

    local path = ensure_writable_dir() .. "waf-rule-stats.json"
    local tmp_path = path .. ".tmp"
    local f = io.open(tmp_path, "w")
    if not f then return end
    local encoded, err = json.encode(stats)
    if not encoded then
        ngx.log(ngx.WARN, "waf-rule-manager: stats persist encode failed: ", tostring(err))
        f:close()
        os.remove(tmp_path)
        return
    end
    f:write(encoded)
    f:close()
    os.rename(tmp_path, path)
end

-- ---------------------------------------------------------------------------
-- restore_rule_stats  — re-populate per-rule stats from disk after restart.
--                        Only the first worker actually loads.
-- ---------------------------------------------------------------------------
function _M.restore_rule_stats()
    local shared = ngx.shared.vn_config
    if not shared then return end

    -- Only restore once across all workers
    if not shared:add("waf_rule_stats:restored", 1) then return end

    local path = ensure_writable_dir() .. "waf-rule-stats.json"
    local f = io.open(path, "r")
    if not f then return end
    local content = f:read("*all")
    f:close()
    if not content or content == "" then return end
    local ok, stats = pcall(json.decode, content)
    if not ok or type(stats) ~= "table" then return end

    local count = 0
    local idx_parts = {}
    for rule_id, data in pairs(stats) do
        shared:set(STATS_PREFIX .. rule_id, json.encode(data))
        idx_parts[#idx_parts + 1] = rule_id
        count = count + 1
    end
    if #idx_parts > 0 then
        shared:set(STATS_INDEX_KEY, table.concat(idx_parts, "\n") .. "\n", 0)
    end
    ngx.log(ngx.NOTICE, "waf-rule-manager: restored stats for ", count, " rules")
end

-- ---------------------------------------------------------------------------
-- rollback  -- restore rules from a previous version in history
-- ---------------------------------------------------------------------------
function _M.rollback(rule_id, target_version)
    local history = _M.get_history(100)
    for _, record in ipairs(history) do
        if record.version == target_version then
            if not record.rule_data then
                return false, "version " .. tostring(target_version) .. " has no rule data"
            end
            local rules = record.rule_data
            -- If rule_id is provided, verify it exists in the restored set
            if rule_id and #rule_id > 0 then
                local found = false
                for _, r in ipairs(rules) do
                    if r.id == rule_id then
                        found = true
                        break
                    end
                end
                if not found then
                    return false, "rule not found in version: " .. tostring(target_version)
                end
            end
            return _M.save_rules(rules, "rollback")
        end
    end
    return false, "version not found in history"
end

-- ---------------------------------------------------------------------------
-- reload  — force reload rules from file into shared dict
-- ---------------------------------------------------------------------------
function _M.reload()
    local rules_obj = _M.load_from_file()
    if not rules_obj then
        return false, "no rules file found"
    end
    return _M.save_rules(rules_obj.rules, "reload")
end

return _M