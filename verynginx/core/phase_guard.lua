-- -*- coding: utf-8 -*-
-- @Date    : 2026-10-22
-- @Author  : VeryNginx v2
-- @Disc    : per-client-request pipeline marker that survives internal redirects
--
-- The access phase re-enters with a fresh context on EVERY internal
-- redirect: the index module (`/` -> `/index.php`), the try_files
-- fallback, and the proxy path's ngx.exec("@vn_proxy"). The redirect
-- discards ngx.ctx, and it re-runs the server-level rewrite phase, where
-- the `set` directives reset every $vn_* request variable to its default
-- (measured in production: $vn_in_exec and any marker variable read back
-- empty after the redirect). So neither ngx.ctx nor a request variable
-- can carry a "the pipeline already ran" marker to the second pass, and
-- every counting plugin (frequency limit, traffic statistics,
-- ip_reputation) charges the client request once per pass.
--
-- This module keeps the marker in a per-worker Lua table keyed by the
-- request id. $request_id is a built-in variable that is stable across
-- internal redirects of one client request, is untouched by the `set`
-- directives, and module state is not re-created by the redirect. The
-- log phase drops the entry, so the table holds only the in-flight
-- requests of the worker.

local _M = {}

-- request_id -> true: the pipeline ran for this client request
--             -> table: the proxy action data, when the proxy path stored
--                it just before ngx.exec() so a later pass can re-apply
--                the target variables the redirect's re-run `set`
--                directives reset
local marked = {}
local marked_count = 0

-- A per-worker cap so a request whose log phase never ran (an aborted
-- request) cannot grow the table unboundedly. The cap is generous; when
-- it trips, only the oldest entries are forgotten and those requests
-- fall back to the pre-guard behaviour for the rest of their lifetime.
local CAP = 16384

local function rid()
    local ok, id = pcall(function() return ngx.var.request_id end)
    if not ok or not id then
        return nil
    end
    return id
end

local function reserve(id)
    if not marked[id] then
        marked_count = marked_count + 1
        if marked_count > CAP then
            marked = {}
            marked_count = 0
        end
    end
end

--- Record that the plugin pipeline ran for this client request. A later
-- pass (any internal redirect) must not run the counting plugins again.
function _M.mark_run()
    local id = rid()
    if not id then
        return
    end
    reserve(id)
    marked[id] = true
end

--- Record that the proxy path exec'd, storing the proxy action so a later
-- pass can re-apply the target variables.
-- @param action_data table: the PROXY action data (host/port/scheme/sni)
function _M.mark_executed(action_data)
    local id = rid()
    if not id then
        return
    end
    reserve(id)
    marked[id] = action_data
end

--- Did this client request already go through the pipeline?
-- @return boolean
function _M.marked()
    local id = rid()
    return id ~= nil and marked[id] ~= nil
end

--- The proxy action data stored by the first pass, or nil when the proxy
-- path did not exec.
-- @return table|nil
function _M.stored_action()
    local id = rid()
    if not id then
        return nil
    end
    local v = marked[id]
    return type(v) == "table" and v or nil
end

--- Did the proxy path exec() for this client request?
-- @return boolean
function _M.executed()
    return _M.stored_action() ~= nil
end

--- Drop this request's entry. Called from the log phase. The log phase
-- runs once per client request (internal redirects do not re-run it), so
-- the entry is gone by the time the next request with the same worker
-- comes in.
function _M.drop()
    local id = rid()
    if id and marked[id] ~= nil then
        marked[id] = nil
        marked_count = marked_count - 1
    end
end

return _M
