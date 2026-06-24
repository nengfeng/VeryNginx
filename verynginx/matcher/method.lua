-- @Disc: Method matcher - Phase 2 implementation
local _M = {}
function _M.test(condition, ctx)
    local method = ctx.request.method
    local op, val = condition.operator, condition.value
    if op == "=" then return method == val end
    if op == "≈" then return ngx.re.find(method, val, "isjo") ~= nil end
    if op == "!≈" then return ngx.re.find(method, val, "isjo") == nil end
    if op == "*" then return true end
    return false
end
return _M