local _M = {}
local compare = require "matcher.compare"
function _M.test(condition, ctx)
    return compare.match(ctx.request.remote_addr, condition.operator, condition.value)
end
return _M