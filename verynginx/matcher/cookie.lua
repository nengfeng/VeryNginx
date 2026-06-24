-- @Disc: Cookie matcher - Phase 2 implementation
local _M = {}
function _M.test(condition, ctx)
    local cookie = require "cookie"
    local cookie_obj, err = cookie:new()
    if not cookie_obj then return false end
    local fields = cookie_obj:get_all()
    if not fields then return false end
    local name_op, name_val = condition.name_operator, condition.name_value
    local op, val = condition.operator, condition.value
    for k, v in pairs(fields) do
        local name_ok = (name_op == "*") or (name_op == "=" and k == name_val) or (name_op == "≈" and ngx.re.find(k, name_val, "isjo"))
        if name_ok then
            if op == "=" then return v == val end
            if op == "≈" then return ngx.re.find(v, val, "isjo") ~= nil end
            if op == "*" then return true end
        end
    end
    return false
end
return _M