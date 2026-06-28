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
local json = require("dkjson")
local config = require("core.config")
local matcher = require("matcher.init")


-- ---------------------------------------------------------------------------
-- Shared dict key prefixes
-- ---------------------------------------------------------------------------
local CACHE_PREFIX  = "waf_rules:chunk:"
local META_KEY      = "waf_rules:meta"
local VERSION_KEY   = "waf_rules_version"
local STATS_PREFIX  = "waf_rule_stats:"
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
-- Persisted file path helper
-- ---------------------------------------------------------------------------
local function rules_path()
    return config.resolve_path() .. "configs/waf-rules.json"
end

local function history_path()
    return config.resolve_path() .. "configs/waf-rules-history.json"
end

local function backup_prefix()
    return config.resolve_path() .. "configs/waf-rules-backup-"
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
                for i = 1, meta.chunk_count do
                    local chunk_json = shared:get(CACHE_PREFIX .. i)
                    if chunk_json then
                        local ok2, chunk = pcall(json.decode, chunk_json)
                        if ok2 and chunk then
                            chunks[tostring(i)] = chunk
                        end
                    end
                end
                if next(chunks) then
                    return {
                        version   = meta.version,
                        timestamp = meta.timestamp,
                        rules     = unchunk_rules(chunks)
                    }
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
    if not f then return nil end
    local content = f:read("*all")
    f:close()
    if not content or content == "" then return nil end
    local ok, data = pcall(json.decode, content)
    if not ok or not data then return nil end
    if type(data) == "table" and data.rules then
        return {
            version   = data.version or 1,
            timestamp = data.timestamp,
            rules     = data.rules
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
function _M.save_rules(rules)
    if type(rules) ~= "table" then
        return false, "rules must be a table"
    end

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
            local bk_path = backup_prefix() .. tostring(ngx.time()) .. ".json"
            local bf = io.open(bk_path, "w")
            if bf then
                bf:write(old_data)
                bf:close()
            end
        end
    end

    -- 2. Prune old backups (keep newest 10)
    local function prune_backups()
        local dir = config.resolve_path() .. "configs/"
        local fh = io.popen('ls -1t "' .. dir .. '"waf-rules-backup-* 2>/dev/null', "r")
        if not fh then return end
        local backups = {}
        for line in fh:lines() do
            backups[#backups + 1] = line
        end
        fh:close()
        for i = 11, #backups do
            os.remove(backups[i])
        end
    end
    prune_backups()

    -- 3. Atomic write
    local tmp_path = path .. ".tmp"
    local f = io.open(tmp_path, "w")
    if not f then return false, "cannot open temp file" end
    local encoded, err = json.encode(data, { indent = true })
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
    _M.record_history(rules, current_version, timestamp)

    return true
end

-- ---------------------------------------------------------------------------
-- record_history  — append a snapshot to the history file
-- ---------------------------------------------------------------------------
function _M.record_history(rules, version, timestamp)
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
        action    = "update",
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
        local encoded = json.encode(history, { indent = true })
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
    local save_ok, save_err = _M.save_rules(rules)
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
            -- Preserve runtime stats
            updates.hit_count        = r.hit_count
            updates.last_triggered   = r.last_triggered
            updates.last_matched_uri = r.last_matched_uri

            updates.updated_at = os.date("!%Y-%m-%dT%H:%M:%SZ")
            updates.version    = (r.version or 1) + 1

            local merged = _M.merge_rule(r, updates)
            rules[i] = merged
            local save_ok, save_err = _M.save_rules(rules)
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
            return _M.save_rules(rules)
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
    local count = shared:incr(key, 1, 1, window)
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
-- record_hit  — push a hit event into the async buffer (O(1), non-blocking)
-- ---------------------------------------------------------------------------
function _M.record_hit(rule_id, ctx)
    local shared = ngx.shared.vn_config
    if not shared then return end

    local hit_data = table.concat({
        rule_id,
        tostring(ngx.time()),
        ctx.request.uri or "",
        ctx.request.remote_addr or "",
        ctx.request.method or "GET"
    }, "|")

    local idx = shared:incr(HIT_PREFIX .. "tail", 1, 0)
    shared:set(HIT_PREFIX .. tostring(idx), hit_data)
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

    local max_process = math.min(tail - head, 500)

    local stats_agg = {}
    for i = 1, max_process do
        local key = HIT_PREFIX .. tostring(head + i)
        local hit_data = shared:get(key)
        if hit_data then
            shared:delete(key)
            -- Format: rule_id|timestamp|uri|ip|method
            local rule_id, ts_str, uri = hit_data:match("^([^|]*)|([^|]*)|([^|]*)")
            if rule_id and #rule_id > 0 then
                local ts = tonumber(ts_str)
                if not stats_agg[rule_id] then
                    stats_agg[rule_id] = { hit_count = 0, last_triggered = 0, last_matched_uri = "" }
                end
                local agg = stats_agg[rule_id]
                agg.hit_count = agg.hit_count + 1
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
        if agg.last_triggered < (existing.last_triggered or 0) then
            agg.last_triggered   = existing.last_triggered
            agg.last_matched_uri = existing.last_matched_uri or ""
        end

        shared:set(stats_key, json.encode(agg))
    end
end

-- ---------------------------------------------------------------------------
-- init_worker  — set up the periodic stats flush timer
-- ---------------------------------------------------------------------------
function _M.init_worker()
    local ok, err = ngx.timer.every(30, function()
        _M.flush_hit_stats()
    end)
    if not ok then
        ngx.log(ngx.ERR, "waf-rule-manager: failed to create flush timer: ", tostring(err))
    end
end

-- ---------------------------------------------------------------------------
-- rollback  — restore rules from a previous version in history
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
            return _M.save_rules(rules)
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
    return _M.save_rules(rules_obj.rules)
end

return _M