local _M = {}
local compare = require "matcher.compare"
function _M.test(condition, ctx)
    local host = ctx.request.host or ""
    return compare.match(host, condition.operator, condition.value)
end
return _M