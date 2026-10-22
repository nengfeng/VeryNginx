-- -*- coding: utf-8 -*-
-- @Date    : 2026-10-22
-- @Author  : VeryNginx v2
-- @Disc    : phase re-entry markers for the proxy path's internal redirect
--
-- The proxy path does an internal redirect (ngx.exec("@vn_proxy")) from the
-- access phase. That redirect re-runs the server-level rewrite phase: every
-- `set` directive in the server block re-executes, resetting all $vn_*
-- request variables to their defaults. Measured in production: after the
-- redirect, $vn_in_exec (the exec-loop guard) and any marker set in a
-- request variable all read back as empty. So no marker kept in an nginx
-- request variable can survive to the second pass.
--
-- The redirect also discards ngx.ctx, so on_rewrite.lua creates a fresh
-- context on the second pass and the whole plugin pipeline has no way to
-- know it already ran: every counting plugin (frequency limit, traffic
-- statistics, ip_reputation's request counter) charges the request twice,
-- and the rewrite-phase actions run twice (rewriting the URI a second
-- time). The proxy target variables ($vn_proxy_host/...) are reset to
-- their defaults as well, so @vn_proxy loses the target the first pass
-- computed.
--
-- This module keeps the state in a per-worker Lua table keyed by the
-- request id. $request_id is a built-in variable that is stable across
-- internal redirects and untouched by the `set` directives, and module
-- state is not re-created by the redirect. It survives to the second pass.

local _M = {}

-- request_id -> the proxy action data stored by the first pass before the
-- exec, so the second pass can re-apply the target variables that the
-- redirect's re-run `set` directives reset.
local stored = {}
local stored_count = 0

-- A per-worker cap so a request whose log phase never ran (an aborted
-- request) cannot grow the table unboundedly. The cap is generous; when it
-- trips, only the oldest entries are forgotten and those requests simply
-- fall back to the pre-guard behaviour for the rest of their lifetime.
local CAP = 16384

local function request_id()
    local ok, id = pcall(function() return ngx.var.request_id end)
    if not ok or not id then
        return nil
    end
    return id
end

--- Record that the proxy path executed ngx.exec() for this request,
-- storing the proxy action so a later pass can re-apply it.
-- @param action_data table: the PROXY action data (host/port/scheme/sni)
function _M.mark_executed(action_data)
    local id = request_id()
    if not id then
        return
    end
    if not stored[id] then
        stored_count = stored_count + 1
        if stored_count > CAP then
            stored = {}
            stored_count = 0
        end
    end
    stored[id] = action_data
end

--- Did the proxy path already exec() for this request (an earlier pass)?
-- @return boolean
function _M.executed()
    local id = request_id()
    return id ~= nil and stored[id] ~= nil
end

--- The proxy action data stored by an earlier pass, or nil.
-- @return table|nil
function _M.stored_action()
    local id = request_id()
    if not id then
        return nil
    end
    return stored[id]
end

--- Drop this request's entry. Called from the log phase; the entry is
-- unique per request id, so forgetting it early only matters if the log
-- phase is skipped.
function _M.drop()
    local id = request_id()
    if id and stored[id] then
        stored[id] = nil
        stored_count = stored_count - 1
    end
end

return _M
