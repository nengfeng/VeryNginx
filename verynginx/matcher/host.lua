-- @Disc: Host matcher - Phase 2 implementation
local _M = {}
function _M.test(condition, ctx)
    local host = ctx.request.host or ""
    local op, val = condition.operator, condition.value
    if op == "=" then return host == val end
    if op == "≈" then return ngx.re.find(host, val, "isjo") ~= nil end
    if op == "!≈" then return ngx.re.find(host, val, "isjo") == nil end
    if op == "*" then return true end
    return false
end
return _M