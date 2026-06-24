-- @Disc: IP matcher - Phase 2 implementation
local _M = {}
function _M.test(condition, ctx)
    local ip = ctx.request.remote_addr
    local op, val = condition.operator, condition.value
    if op == "=" then return ip == val end
    if op == "≈" then return ngx.re.find(ip, val, "isjo") ~= nil end
    if op == "!≈" then return ngx.re.find(ip, val, "isjo") == nil end
    if op == "*" then return true end
    return false
end
return _M