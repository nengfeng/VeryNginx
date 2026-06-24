-- @Disc: Referer matcher - Phase 2 implementation
local _M = {}
function _M.test(condition, ctx)
    local ref = ctx.request.referer or ""
    local op, val = condition.operator, condition.value
    if op == "=" then return ref == val end
    if op == "≈" then return ngx.re.find(ref, val, "isjo") ~= nil end
    if op == "!≈" then return ngx.re.find(ref, val, "isjo") == nil end
    if op == "*" then return true end
    return false
end
return _M