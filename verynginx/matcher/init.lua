-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : matcher registry - register, resolve, and execute matchers

local _M = {}
local json = pcall(require, "cjson") and require("cjson") or require("dkjson")
local config = require "core.config"

_M.registry = {}

-- Condition evaluation priority: lighter checks first for early short-circuit
local _CONDITION_ORDER = {
    Method = 1,
    URI = 2,
    Host = 3,
    UserAgent = 4,
    Referer = 5,
    IP = 6,
    Header = 7,
    Cookie = 8,
    Args = 9,
    Composite = 10,
}

function _M.register(name, handler)
    _M.registry[name] = handler
end

function _M.condition_order()
    return _CONDITION_ORDER
end

--- Pre-compute the per-request hot-path data for a matcher definition:
-- _matcher_crc (match-cache key; avoids a per-request json.encode + crc32)
-- and _sorted_conditions (avoids a per-request allocation + table.sort),
-- then recurse into Composite sub-conditions so nested definitions get the
-- same treatment. Idempotent; called once at config-compile / rule-load
-- time. Both fields must be set together: a crc without the sorted list
-- would leak the "_"-prefixed keys into the condition loop.
function _M.precompute(matcher_def)
    if type(matcher_def) ~= "table" or matcher_def._sorted_conditions then
        return matcher_def
    end
    if not matcher_def._matcher_crc and ngx and ngx.crc32_short then
        -- encode before the "_" keys exist so the crc covers only conditions
        matcher_def._matcher_crc = ngx.crc32_short(json.encode(matcher_def))
    end
    local sorted = {}
    for condition_type, condition in pairs(matcher_def) do
        -- skip our own metadata keys (defensive: also protects the
        -- un-precomputed fallback path in _M.test below)
        if condition_type:sub(1, 1) ~= "_" then
            sorted[#sorted + 1] = { type = condition_type, cond = condition,
                                    order = _CONDITION_ORDER[condition_type] or 50 }
        end
    end
    table.sort(sorted, function(a, b) return a.order < b.order end)
    matcher_def._sorted_conditions = sorted
    for _, entry in ipairs(sorted) do
        local c = entry.cond
        if entry.type == "Composite" and type(c) == "table"
            and type(c.conditions) == "table" then
            for _, sub in ipairs(c.conditions) do
                if type(sub) == "table" then _M.precompute(sub) end
            end
        end
    end
    return matcher_def
end

--- Resolve a rule's matcher definition.
-- Checks _matcher_def first (pre-resolved by config compile), then
-- looks up string names in config.matcher, then uses inline table.
function _M.resolve(rule)
    local matcher_def = rule._matcher_def
    if not matcher_def and type(rule.matcher) == "string" then
        matcher_def = config.matcher and config.matcher[rule.matcher]
    end
    if not matcher_def and type(rule.matcher) == "table" then
        matcher_def = rule.matcher
    end
    return matcher_def
end

function _M.test(matcher_def, ctx)
    if not matcher_def or next(matcher_def) == nil then
        return true
    end

    local cache_key = matcher_def and matcher_def._matcher_crc
    if not cache_key then
        cache_key = ngx and ngx.crc32_short and ngx.crc32_short(json.encode(matcher_def))
    end
    if cache_key and ctx and ctx.match_cache and ctx.match_cache[cache_key] ~= nil then
        return ctx.match_cache[cache_key]
    end

    local result = true
    -- Use pre-sorted conditions if available (compiled at config time)
    local sorted = matcher_def._sorted_conditions
    if not sorted then
        sorted = {}
        for condition_type, condition in pairs(matcher_def) do
            -- skip "_"-prefixed metadata keys (_matcher_crc etc.) so a
            -- partially precomputed def can never be treated as a condition
            if condition_type:sub(1, 1) ~= "_" then
                sorted[#sorted + 1] = { type = condition_type, cond = condition,
                                        order = _CONDITION_ORDER[condition_type] or 50 }
            end
        end
        table.sort(sorted, function(a, b) return a.order < b.order end)
    end
    for _, entry in ipairs(sorted) do
        local handler = _M.registry[entry.type]
        if handler then
            local ok = handler(entry.cond, ctx)
            if not ok then
                result = false
                break
            end
        else
            result = false
            break
        end
    end

    if cache_key and ctx and ctx.match_cache and ctx.match_cache_size < 128 then
        ctx.match_cache[cache_key] = result
        ctx.match_cache_size = (ctx.match_cache_size or 0) + 1
    end
    return result
end

return _M