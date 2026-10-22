-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Frequency Rule ID management

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
--
-- READ-ONLY. This used to assign the missing ids itself and save the config
-- from inside a status read — a GET request writing the configuration, with
-- an atomic_mutate on the hot path of every panel poll. Ids are assigned when
-- a rule is saved (api/controllers/frequency.lua) and by the migration tool
-- (core/frequency/rule_id_migration.lua); the frequency plugin tolerates a
-- rule without one, so there is nothing to fix silently here.
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
    if with_id == total and total > 0 then
        return { status = "completed", total = total, id_count = with_id, ids = ids }
    end
    return { status = "pending", total = total, with_id = with_id, missing = missing }
end

return _M
