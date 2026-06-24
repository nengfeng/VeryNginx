-- @Disc: Composite matcher (AND/OR/NOT) - Phase 2 implementation
local _M = {}
local matcher = require "matcher.init"
function _M.test(condition, ctx)
    local op = condition.operator
    local sub = condition.conditions
    if not sub or #sub == 0 then return true end
    if op == "AND" then
        for _, m in ipairs(sub) do
            if not matcher.test(m, ctx) then return false end
        end
        return true
    elseif op == "OR" then
        for _, m in ipairs(sub) do
            if matcher.test(m, ctx) then return true end
        end
        return false
    elseif op == "NOT" then
        return not matcher.test(sub[1], ctx)
    end
    return true
end
return _M