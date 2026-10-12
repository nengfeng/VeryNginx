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

    -- Body read failed, or args were truncated (tail dropped).
    -- A condition that explicitly sets on_body_error keeps fail-closed
    -- ("match"/"fail_closed") or fail-open ("skip") semantics for
    -- uninspectable bodies.
    --
    -- The GLOBAL body.on_error policy no longer fans out to every Args
    -- condition: that masquerade made whichever rule happened to sort first
    -- claim the hit (typically vn_sqli_0001, pri=10) and 403'd legitimate
    -- large bodies on default installs. plugin/filter now records one honest
    -- synthetic hit (vn_body_uninspectable) for uninspectable requests
    -- instead.
    if ctx.request._body_error or ctx.request._uri_args_error then
        local cond_policy = condition.on_body_error
        if cond_policy then
            return cond_policy == "match" or cond_policy == "fail_closed"
        end
        return false
    end
    return false
end

function _M._test_args(args, name_op, name_val, op, val)
    -- Wildcard name match ("*"): the parameter NAME is attacker-controlled
    -- data too — backends echo it in errors, search pages and routing — so
    -- test the key against the payload matcher as well. Conditions with an
    -- explicit name pattern keep name-scoped semantics untouched.
    local wildcard = name_op == "*"
    for k, v in pairs(args) do
        if compare.match(k, name_op, name_val) then
            if wildcard and compare.match(k, op, val) then return true end
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