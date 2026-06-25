-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : action registry - register and dispatch action handlers

local _M = {}

_M.action_handlers = {}

function _M.register(name, handler)
    _M.action_handlers[name] = handler
end

function _M.get(name)
    return _M.action_handlers[name]
end

setmetatable(_M, {
    __index = function(t, k)
        return t.action_handlers[k]
    end
})

-- Register built-in actions
_M.register("accept", function(rule, ctx)
    return { type = "accept" }
end)

_M.register("block", function(rule, ctx)
    return { type = "block", data = { code = rule.code or 403, response = rule.response } }
end)

_M.register("redirect", function(rule, ctx)
    return { type = "redirect", data = { url = rule.to_uri, code = rule.code or 302 } }
end)

_M.register("rewrite", function(rule, ctx)
    return { type = "rewrite", data = { uri = rule.to_uri } }
end)

_M.register("response", function(rule, ctx)
    return { type = "response", data = { response = rule.response, code = rule.code } }
end)

_M.register("proxy", function(rule, ctx)
    return { type = "proxy", data = { rule = rule } }
end)

_M.register("static", function(rule, ctx)
    return { type = "static", data = { rule = rule } }
end)

return _M