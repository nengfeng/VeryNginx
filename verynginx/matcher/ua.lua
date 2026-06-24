-- @Disc: UserAgent matcher - Phase 2 implementation
local _M = {}
function _M.test(condition, ctx)
    local ua = ctx.request.user_agent or ""
    local op, val = condition.operator, condition.value
    if op == "=" then return ua == val end
    if op == "≈" then return ngx.re.find(ua, val, "isjo") ~= nil end
    if op == "!≈" then return ngx.re.find(ua, val, "isjo") == nil end
    if op == "*" then return true end
    return false
end
return _M