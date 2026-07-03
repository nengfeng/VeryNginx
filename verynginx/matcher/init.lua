-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : matcher registry - register, resolve, and execute matchers

local _M = {}
local cjson = pcall(require, "cjson") and require("cjson") or require("dkjson")

_M.registry = {}

function _M.register(name, handler)
    _M.registry[name] = handler
end

--- Resolve a rule's matcher definition.
-- Checks _matcher_def first (pre-resolved by config compile), then
-- looks up string names in config.matcher, then uses inline table.
function _M.resolve(rule)
    local config = require "core.config"
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
        cache_key = ngx and ngx.crc32_short and ngx.crc32_short(cjson.encode(matcher_def))
    end
    if cache_key and ctx and ctx.match_cache and ctx.match_cache[cache_key] ~= nil then
        return ctx.match_cache[cache_key]
    end

    local result = true
    for condition_type, condition in pairs(matcher_def) do
        local handler = _M.registry[condition_type]
        if handler then
            local ok = handler(condition, ctx)
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