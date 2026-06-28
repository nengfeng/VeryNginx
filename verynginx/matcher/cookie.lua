-- @Disc: Cookie matcher - Phase 2 implementation
local _M = {}
local compare = require "matcher.compare"
function _M.test(condition, _)
    local cookie = require "cookie"
    local cookie_obj = cookie:new()
    if not cookie_obj then return false end
    local fields = cookie_obj:get_all()
    if not fields then return false end
    local name_op, name_val = condition.name_operator, condition.name_value
    local op, val = condition.operator, condition.value
    for k, v in pairs(fields) do
        if compare.match(k, name_op, name_val) then
            return compare.match(v, op, val)
        end
    end
    return false
end
return _M