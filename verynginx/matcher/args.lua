-- @Disc: Args matcher (lazy body read) - Phase 2 implementation
local _M = {}

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
    if ctx.request._body_error then
        local policy = condition.on_body_error or (require("core.config").body and require("core.config").body.on_error) or "skip"
        return policy == "match" or policy == "fail_closed"
    end
    return false
end

function _M._test_args(args, name_op, name_val, op, val)
    for k, v in pairs(args) do
        if _M._match_var(name_op, name_val, k) then
            if type(v) == "table" then
                for _, arg_v in ipairs(v) do
                    if _M._match_var(op, val, arg_v) then return true end
                end
            else
                if _M._match_var(op, val, v) then return true end
            end
        end
    end
    return false
end

function _M._match_var(op, pattern, target)
    if op == "=" then return target == pattern end
    if op == "≈" then return type(target) == "string" and ngx.re.find(target, pattern, "isjo") ~= nil end
    if op == "!≈" then return type(target) ~= "string" or ngx.re.find(target, pattern, "isjo") == nil end
    if op == "*" then return true end
    return false
end

return _M