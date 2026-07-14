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
    UA = 4,
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
            sorted[#sorted + 1] = { type = condition_type, cond = condition,
                                    order = _CONDITION_ORDER[condition_type] or 50 }
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