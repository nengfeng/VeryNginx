local _M = {}

function _M.match(value, op, pattern)
    if op == "=" then return value == pattern end
    if op == "≈" then return type(value) == "string" and ngx.re.find(value, pattern, "isjo") ~= nil end
    if op == "!≈" then return type(value) ~= "string" or ngx.re.find(value, pattern, "isjo") == nil end
    if op == "*" then return true end
    return false
end

return _M
