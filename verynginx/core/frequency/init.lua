-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Frequency Rule ID management + v2 counter namespace helpers

local _M = {}

local config = require "core.config"

-- ---------------------------------------------------------------------------
-- Returns a stable ID for a frequency rule by its array index.
-- Returns nil if the rule has not been migrated (no stable ID yet).
-- ---------------------------------------------------------------------------
function _M.get_rule_id(rule_index)
    local rules = config.rule and config.rule.frequency_limit
    if not rules or type(rules) ~= "table" then return nil end
    local rule = rules[rule_index]
    if not rule or type(rule) ~= "table" then return nil end
    return rule.id
end

-- ---------------------------------------------------------------------------
-- Returns { id = rule_index } for all rules with stable IDs.
-- ---------------------------------------------------------------------------
function _M.id_to_index_map()
    local rules = config.rule and config.rule.frequency_limit
    if not rules or type(rules) ~= "table" then return {} end
    local map = {}
    for i, rule in ipairs(rules) do
        if rule and type(rule) == "table" and rule.id then
            map[rule.id] = i
        end
    end
    return map
end

-- ---------------------------------------------------------------------------
-- Returns migration status:
--   { status = "pending", total = N, with_id = M, missing = K }
--   or { status = "completed", total = N, id_count = M, ids = {...} }
-- ---------------------------------------------------------------------------
function _M.get_migration_status()
    local rules = config.rule and config.rule.frequency_limit
    if not rules or type(rules) ~= "table" then
        return { status = "no_rules" }
    end
    local total = #rules
    local with_id = 0
    local missing = 0
    local ids = {}
    for _, rule in ipairs(rules) do
        if rule and type(rule) == "table" then
            if rule.id and rule.id ~= "" then
                with_id = with_id + 1
                ids[#ids + 1] = rule.id
            else
                missing = missing + 1
            end
        end
    end
    -- Auto-assign IDs to rules missing them (migration on read).
    if missing > 0 and total > 0 then
        local cfg_mod = require "core.config"
        for _, rule in ipairs(rules) do
            if rule and type(rule) == "table" and (not rule.id or rule.id == "") then
                rule.id = "freq_" .. tostring(ngx.time()) .. "_" .. tostring(math.random(1000, 9999))
                ids[#ids + 1] = rule.id
            end
        end
        cfg_mod.atomic_mutate(function(cfg)
            cfg.rule.frequency_limit = rules
            return cfg
        end)
        return { status = "completed", total = total, id_count = total, ids = ids }
    end
    if with_id == total and total > 0 then
        return { status = "completed", total = total, id_count = with_id, ids = ids }
    end
    return { status = "pending", total = total, with_id = with_id, missing = missing }
end

-- ---------------------------------------------------------------------------
-- V2 key builder contract:
-- limiter.build_key() returns ONLY the dimension portion (no prefix).
-- The caller assembles the full key namespace:
--   Count:        fl:v2:count:<encoded_rule_id>:<encoded_dimension>
--   CC violation: fl:v2:kernel:violation:<encoded_rule_id>:<ip>:<slot>
-- ---------------------------------------------------------------------------
local function rule_key(rule_or_id)
    local id
    if type(rule_or_id) == "table" then
        id = rule_or_id.id
    else
        id = rule_or_id
    end
    if not id or id == "" then
        error("frequency rule has not been assigned a stable ID (run migration first)")
    end
    return "fl:v2:count:" .. id
end

function _M.counter_namespace(rule_or_id)
    return rule_key(rule_or_id)
end

-- ---------------------------------------------------------------------------
-- Check if v2 counter namespace has been cut over (i.e., migration done).
-- ---------------------------------------------------------------------------
function _M.is_cutover_complete()
    local status = _M.get_migration_status()
    -- No rules means nothing to migrate — treat as already cut over.
    if status.status == "no_rules" then
        local s = ngx.shared.frequency_limit
        if s and not s:get("fl:v2:cutover_epoch") then
            s:set("fl:v2:cutover_epoch", tostring(ngx.time()))
            s:incr("fl:v2:config_generation", 1, 0)
        end
        return true
    end
    if status.status == "completed" then
        -- Verify shared-state cutover_epoch; write if missing (e.g. dict evicted)
        local s = ngx.shared.frequency_limit
        if s then
            if s:get("fl:v2:cutover_epoch") then
                return true
            end
            -- dict may have been cleared; restore marker from persisted status
            local epoch = status.cutover_epoch or tostring(ngx.time())
            s:set("fl:v2:cutover_epoch", epoch)
            s:incr("fl:v2:config_generation", 1, 0)
            return true
        end
    end
    return false
end

-- ---------------------------------------------------------------------------
-- Record first-exceed evidence for CC promotion (called by init.lua).
-- Returns true if evidence was newly recorded (transition point).
-- ---------------------------------------------------------------------------
function _M.record_violation_if_first(rule, ip, _ctx)
    if not rule or not ip then return false end
    local id = type(rule) == "table" and rule.id or rule
    if not id then return false end
    local ev = require "core.kernel_blocking.evidence"
    local window = (type(rule) == "table" and rule.window) or 60
    ev.record_cc_violation_evidence(id, ip, window)
    return true
end

return _M
