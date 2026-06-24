-- @Disc: URI matcher - Phase 2 implementation
local _M = {}
function _M.test(condition, ctx)
    local uri = ctx.request.uri
    local op, val = condition.operator, condition.value
    if op == "=" then return uri == val end
    if op == "≈" then return ngx.re.find(uri, val, "isjo") ~= nil end
    if op == "!≈" then return ngx.re.find(uri, val, "isjo") == nil end
    if op == "*" then return true end
    return false
end
return _M