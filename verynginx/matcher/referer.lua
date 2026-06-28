local _M = {}
local compare = require "matcher.compare"
function _M.test(condition, ctx)
    return compare.match(ctx.request.referer or "", condition.operator, condition.value)
end
return _M