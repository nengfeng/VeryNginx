-- @Disc: Header matcher - Phase 2 implementation
local _M = {}
local compare = require "matcher.compare"
local config = require "core.config"
function _M.test(condition, _)
    local max_headers = (config and config.headers and config.headers.max_count) or 1000
    local headers = ngx.req.get_headers(max_headers)
    local name_op, name_val = condition.name_operator, condition.name_value
    local op, val = condition.operator, condition.value
    for k, v in pairs(headers) do
        if v ~= nil then
            local ks, vs = tostring(k), tostring(v)
            if compare.match(ks, name_op, name_val) then
                -- Keep scanning: multiple header names can match the pattern.
                -- Returning on the first name match let a safe header shadow a
                -- malicious sibling when the table iteration order was unlucky.
                if compare.match(vs, op, val) then return true end
            end
        end
    end
    return false
end
return _M