-- @Disc: Header matcher - Phase 2 implementation
local _M = {}
local compare = require "matcher.compare"
function _M.test(condition, _)
    local headers = ngx.req.get_headers()
    local name_op, name_val = condition.name_operator, condition.name_value
    local op, val = condition.operator, condition.value
    for k, v in pairs(headers) do
        if v ~= nil then
            local ks, vs = tostring(k), tostring(v)
            if compare.match(ks, name_op, name_val) then
                return compare.match(vs, op, val)
            end
        end
    end
    return false
end
return _M