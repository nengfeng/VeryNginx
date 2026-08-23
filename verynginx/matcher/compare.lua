local _M = {}

local MAX_COMPILED = 256
-- __count MUST be initialized here: get_compiled reads it BEFORE the first
-- insert, and a nil would raise "compare number with nil" on a fresh worker's
-- very first regex evaluation.
local compiled_cache = { __count = 0 }

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
    if op == "≈" or op == "!≈" then
        if type(value) ~= "string" then return false end
        local matched
        local re = get_compiled(pattern)
        if re then
            matched = ngx.re.match(value, re) ~= nil
        elseif type(ngx.re) ~= "table" or type(ngx.re.compile) ~= "function" then
            -- Minimal environments (unit-test rigs) without the compile API:
            -- degrade to find(). Guarded so a bad pattern can't raise here.
            local okf, _, ferr = pcall(ngx.re.find, value, pattern, "isjo")
            if not okf then return false end
            matched = ferr ~= nil
        else
            -- Compile API present but the PATTERN is invalid ⇒ fail-safe
            -- "never matches". The old fallback re-ran the same bad pattern
            -- through ngx.re.find, which raised and — via the critical-plugin
            -- policy — 503'd every evaluated request until manual disable.
            return false
        end
        if op == "≈" then return matched end
        return not matched
    end
    if op == "*" then return true end
    return false
end

return _M
