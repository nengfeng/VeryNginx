-- @Disc: Args matcher (lazy body read) - Phase 2 implementation
local _M = {}
local compare = require "matcher.compare"

function _M.test(condition, ctx)
    local name_op, name_val = condition.name_operator, condition.name_value
    local op, val = condition.operator, condition.value

    -- Check URI args first (no body read)
    local uri_args = ctx.get_uri_args(ctx)
    if _M._test_args(uri_args, name_op, name_val, op, val) then
        return true
    end

    -- Check body args (lazy read)
    local body_args = ctx.get_body_args(ctx)
    if body_args then
        return _M._test_args(body_args, name_op, name_val, op, val)
    end

    -- Either body read failed, or URI args were truncated (tail dropped).
    -- Apply the configured on_error policy so a hidden payload cannot slip
    -- past the scanner. Default to fail_closed when the policy is missing.
    if ctx.request._body_error or ctx.request._uri_args_error then
        local policy = condition.on_body_error
            or (require("core.config").body and require("core.config").body.on_error)
            or "fail_closed"
        return policy == "match" or policy == "fail_closed"
    end
    return false
end

function _M._test_args(args, name_op, name_val, op, val)
    for k, v in pairs(args) do
        if compare.match(k, name_op, name_val) then
            if type(v) == "table" then
                for _, arg_v in ipairs(v) do
                    if compare.match(arg_v, op, val) then return true end
                end
            else
                if compare.match(v, op, val) then return true end
            end
        end
    end
    return false
end

return _M