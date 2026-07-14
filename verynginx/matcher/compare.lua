local _M = {}

local MAX_COMPILED = 256
local compiled_cache = {}

local function get_compiled(pattern)
    local re = compiled_cache[pattern]
    if re then return re end
    local ok, result = pcall(ngx.re.compile, pattern, "isjo")
    if not ok then return nil end
    if compiled_cache.__count >= MAX_COMPILED then
        compiled_cache = { __count = 0 }
    end
    compiled_cache[pattern] = result
    compiled_cache.__count = (compiled_cache.__count or 0) + 1
    return result
end

function _M.match(value, op, pattern)
    if op == "=" then return value == pattern end
    if op == "≈" then
        if type(value) ~= "string" then return false end
        local re = get_compiled(pattern)
        if re then return ngx.re.match(value, re) ~= nil end
        return ngx.re.find(value, pattern, "isjo") ~= nil
    end
    if op == "!≈" then
        if type(value) ~= "string" then return true end
        local re = get_compiled(pattern)
        if re then return ngx.re.match(value, re) == nil end
        return ngx.re.find(value, pattern, "isjo") == nil
    end
    if op == "*" then return true end
    return false
end

return _M
