-- @Disc: Header matcher - Phase 2 implementation
local _M = {}
function _M.test(condition, ctx)
    local headers = ngx.req.get_headers()
    local name_op, name_val = condition.name_operator, condition.name_value
    local op, val = condition.operator, condition.value
    for k, v in pairs(headers) do
        local ks, vs = tostring(k), tostring(v)
        local name_ok = (name_op == "*") or (name_op == "=" and ks == name_val) or (name_op == "≈" and ngx.re.find(ks, name_val, "isjo"))
        if name_ok then
            if op == "=" then return vs == val end
            if op == "≈" then return ngx.re.find(vs, val, "isjo") ~= nil end
            if op == "*" then return true end
        end
    end
    return false
end
return _M