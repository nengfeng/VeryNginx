-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-08
-- @Author  : VeryNginx v2
-- @Disc    : WAF rule recommender — analyze blocked traffic and suggest new rules

local _M = {}

local json = pcall(require, "cjson") and require("cjson") or require("dkjson")
local config = require "core.config"
local random = require "core.random"

local PREFIX = "waf_rec:"
local INDEX_KEY = PREFIX .. "index"
local LOCK_KEY = PREFIX .. "index_lock"
local LOCK_TTL = 5

-- ---------------------------------------------------------------------------
-- Config
-- ---------------------------------------------------------------------------
local DEFAULTS = {
    enabled = true,
    min_hits = 10,           -- 最少命中次数才生成建议
    window_size = 3600,      -- 分析窗口（秒）
    min_patterns = 3,        -- 同 IP 最少不同 URI 模式怀疑为扫描
}

local function cfg()
    local c = config.waf_recommender
    if not c then return DEFAULTS end
    return {
        enabled = (c.enabled ~= nil and c.enabled) or DEFAULTS.enabled,
        min_hits = c.min_hits or DEFAULTS.min_hits,
        window_size = c.window_size or DEFAULTS.window_size,
        min_patterns = c.min_patterns or DEFAULTS.min_patterns,
    }
end

-- ---------------------------------------------------------------------------
-- URI normalization (same as alerting engine's)
-- ---------------------------------------------------------------------------
local function normalize_uri(uri)
    local p = uri:gsub("%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x", ":uuid")
    p = p:gsub("%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x", ":hex")
    p = p:gsub("%d+", ":id")
    return p
end

-- Convert normalized URI template (with :id/:uuid/:hex placeholders) to regex
-- for the "≈" operator in matcher/uri.lua
local function template_to_regex(tmpl)
    if not tmpl or tmpl == "" then return "" end
    local r = tmpl
    -- Escape regex special chars first (except our placeholders)
    r = r:gsub("([%.%+%*%?%^%$%(%)%[%]%{%}%|])", "%%%1")
    -- Replace placeholders with regex
    -- UUID: strict 8-4-4-4-12 format (not [0-9a-f-]{36} which allows hyphens anywhere)
    r = r:gsub(":uuid", "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    r = r:gsub(":hex", "[0-9a-f]+")
    r = r:gsub(":id", "\\d+")
    return r
end

-- ---------------------------------------------------------------------------
-- Generate rule suggestion from a blocked pattern
-- ---------------------------------------------------------------------------
local function generate_suggestion(pattern, info)
    local category
    local severity

    if pattern:find("/%.%.", 1, true) or pattern:find("/etc/") or pattern:find("/proc/") then
        category = "path_traversal"
        severity = "critical"
    elseif pattern:find("exec") or pattern:find("cmd") or pattern:find("shell") then
        category = "rce"
        severity = "critical"
    elseif pattern:find("select") or pattern:find("union") or pattern:find("'") then
        category = "sqli"
        severity = "high"
    elseif pattern:find("%.env") or pattern:find("%.git") or pattern:find("backup") then
        category = "scanner"
        severity = "medium"
    else
        category = "scanner"
        severity = "medium"
    end

    local suggestion = {
        pattern = pattern,
        category = category,
        severity = severity,
        action = severity == "critical" and "block" or "challenge",
        hit_count = info.count,
        sample_uri = info.sample_uri,
        sample_ip = info.sample_ip,
        first_seen = info.first_seen,
        last_seen = info.timestamp,
        created_at = ngx.time(),
        status = "pending",  -- pending | applied | dismissed
    }

    -- Generate a stable ID from pattern
    suggestion.id = ngx.md5("waf_rec:" .. pattern)

    return suggestion
end

-- ---------------------------------------------------------------------------
-- Analyze blocked hits and generate rule suggestions
-- ---------------------------------------------------------------------------
function _M.analyze()
    local conf = cfg()
    if not conf.enabled then return end

    local s = ngx.shared.vn_config
    if not s then return end

    -- Collect blocked patterns from recent hits
    local patterns = {}
    local now = ngx.time()
    local cutoff = now - conf.window_size

    for ri = 1, 100 do
        local d = s:get("waf_recent_hits:data:" .. ri)
        if d then
            local ok, detail = pcall(json.decode, d)
            if ok and detail then
                -- Only analyze blocked requests within the window
                if detail.timestamp and detail.timestamp >= cutoff
                    and (detail.action or "block") == "block" then
                    local uri = detail.uri or ""
                    local pattern = normalize_uri(uri)
                    if not patterns[pattern] then
                        patterns[pattern] = {
                            count = 0,
                            ips = {},
                            sample_uri = uri,
                            first_seen = detail.timestamp,
                        }
                    end
                    local p = patterns[pattern]
                    p.count = p.count + 1
                    if detail.ip then
                        p.ips[detail.ip] = (p.ips[detail.ip] or 0) + 1
                    end
                    -- Keep earliest first_seen
                    if detail.timestamp and detail.timestamp < (p.first_seen or now) then
                        p.first_seen = detail.timestamp
                    end
                end
            end
        end
    end

    -- Load existing suggestions to avoid duplicates
    local existing = _M.list()
    local existing_map = {}
    for _, r in ipairs(existing) do
        existing_map[r.pattern] = true
    end

    -- Generate new suggestions
    local new_count = 0
    for pattern, info in pairs(patterns) do
        if info.count >= conf.min_hits and not existing_map[pattern] then
            -- Require hits from multiple IPs — a single scanner can trigger
            -- many URIs and would otherwise generate a large number of noise
            -- suggestions.  ip_count >= min_patterns filters those out.
            local ip_count = 0
            for _ in pairs(info.ips) do
                ip_count = ip_count + 1
            end
            if ip_count < conf.min_patterns then
                goto continue
            end

            local suggestion = generate_suggestion(pattern, info)
            _M.add(suggestion)
            new_count = new_count + 1
            ::continue::
        end
    end

    return new_count
end

-- ---------------------------------------------------------------------------
-- CRUD for rule suggestions
-- ---------------------------------------------------------------------------
-- Atomic index mutation via spin-lock with token ownership (TOCTOU-safe across workers).
local function with_index_lock(fn)
    local s = ngx.shared.vn_config
    if not s then return false end
    for _ = 1, 20 do
        local token = random.bytes(8)
        local ok = s:add(LOCK_KEY, token, LOCK_TTL)
        if ok then
            local result = { pcall(fn) }
            -- Only release the lock if we still hold it — prevents a stale
            -- holder from deleting a new holder's lock after TTL expiry.
            if s:get(LOCK_KEY) == token then
                s:delete(LOCK_KEY)
            end
            if result[1] then return true, result[2] end
            return false, result[2]
        end
        ngx.sleep(0.01)
    end
    return false, "index_lock_timeout"
end

local function index_append(id)
    local s = ngx.shared.vn_config
    local index_raw = s:get(INDEX_KEY) or "[]"
    local index = {}
    if type(index_raw) == "string" then
        local ok, t = pcall(json.decode, index_raw)
        if ok and type(t) == "table" then index = t end
    end
    -- Dedup: skip if already present (idempotent re-add).
    for _, v in ipairs(index) do
        if v == id then return end
    end
    table.insert(index, id)
    s:set(INDEX_KEY, json.encode(index), 86400 * 7)
end

local function index_remove(id)
    local s = ngx.shared.vn_config
    local index_raw = s:get(INDEX_KEY) or "[]"
    local index = {}
    if type(index_raw) == "string" then
        local ok, t = pcall(json.decode, index_raw)
        if ok and type(t) == "table" then index = t end
    end
    local filtered = {}
    for _, v in ipairs(index) do
        if v ~= id then table.insert(filtered, v) end
    end
    s:set(INDEX_KEY, json.encode(filtered), 86400 * 7)
end

function _M.add(suggestion)
    local s = ngx.shared.vn_config
    if not s then return false end

    local key = PREFIX .. suggestion.id
    s:set(key, json.encode(suggestion), 86400 * 7)

    -- Atomic index update (TOCTOU-safe across workers)
    local ok, err = with_index_lock(function()
        index_append(suggestion.id)
    end)
    if not ok then
        -- Entry written but index update failed — log and continue.
        -- The orphaned entry will be skipped by list() (it just won't appear).
        ngx.log(ngx.WARN, "waf_recommender: index append failed: ", tostring(err))
    end
    return true
end

function _M.list()
    local s = ngx.shared.vn_config
    if not s then return {} end

    local index_raw = s:get(INDEX_KEY)
    if not index_raw then return {} end
    local ok, index = pcall(json.decode, index_raw)
    if not ok or type(index) ~= "table" then return {} end

    local results = {}
    for _, id in ipairs(index) do
        local raw = s:get(PREFIX .. id)
        if raw then
            local ok2, item = pcall(json.decode, raw)
            if ok2 and item then
                table.insert(results, item)
            end
        end
    end
    return results
end

function _M.get(id)
    local s = ngx.shared.vn_config
    if not s then return nil end
    local raw = s:get(PREFIX .. id)
    if not raw then return nil end
    local ok, item = pcall(json.decode, raw)
    if not ok then return nil end
    return item
end

function _M.update_status(id, status)
    local item = _M.get(id)
    if not item then return false, "not found" end
    item.status = status
    local s = ngx.shared.vn_config
    if not s then return false end
    s:set(PREFIX .. id, json.encode(item), 86400 * 7)
    return true
end

function _M.delete(id)
    local s = ngx.shared.vn_config
    if not s then return false end
    s:delete(PREFIX .. id)
    -- Atomic index update (TOCTOU-safe across workers)
    local ok, err = with_index_lock(function()
        index_remove(id)
    end)
    if not ok then
        ngx.log(ngx.WARN, "waf_recommender: index remove failed: ", tostring(err))
    end
    return true
end

-- ---------------------------------------------------------------------------
-- Apply a suggestion as a real WAF rule
-- ---------------------------------------------------------------------------
function _M.apply(id)
    local item = _M.get(id)
    if not item then return false, "not found" end
    if item.status ~= "pending" then return false, "already " .. item.status end

    -- Build the WAF rule
    local rule = {
        id = "rec_" .. item.id:sub(1, 8),
        name = "Auto: " .. item.category .. " - " .. item.pattern:sub(1, 40),
        category = item.category,
        severity = item.severity,
        action = item.action,
        enable = true,
        priority = 50,
        matcher = item.pattern and { URI = { operator = "≈", value = template_to_regex(item.pattern) } } or {},
    }

    -- Use waf_manager to add the rule
    local waf_manager = require "waf-rule-manager"
    local rules_obj = waf_manager.load_rules()
    local rules = rules_obj and rules_obj.rules or {}
    table.insert(rules, rule)
    local ok, err = waf_manager.save_rules(rules)
    if not ok then
        return false, "save failed: " .. tostring(err)
    end

    -- Reload rules
    waf_manager.reload()
    _M.update_status(id, "applied")
    return true
end

-- ---------------------------------------------------------------------------
-- Get stats
-- ---------------------------------------------------------------------------
function _M.get_stats()
    local list = _M.list()
    local stats = { total = 0, pending = 0, applied = 0, dismissed = 0 }
    for _, item in ipairs(list) do
        stats.total = stats.total + 1
        stats[item.status] = (stats[item.status] or 0) + 1
    end
    return stats
end

return _M