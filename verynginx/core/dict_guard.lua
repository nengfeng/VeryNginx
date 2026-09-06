-- -*- coding: utf-8 -*-
-- @Disc    : shared-dict write failure guard (§3.4)
--
-- ngx.shared.DICT set/incr/add return (nil, err) on failure — most commonly
-- "no memory" when the dict is full. Dropping that return silently loses
-- data (audit entries, alert state, counters, indexes) until the dict
-- pressure clears, with no way for an operator to notice. Callers capture
-- the result and route failures here: one throttled WARN per scope instead
-- of either silence or a per-request log flood. (metrics.lua additionally
-- counts its own drops via record_drop — that contract is unchanged.)

local _M = {}

local WARN_INTERVAL = 30
local last_warn = {}

--- Record a failed shared-dict write.
-- @param scope string: logical owner, e.g. "audit", "alerting.state"
-- @param op string: "set" | "incr" | "add"
-- @param err string|nil: error from the dict call
function _M.write_failed(scope, op, err)
    local now = ngx.now()
    local last = last_warn[scope]
    if last and (now - last) < WARN_INTERVAL then
        return
    end
    last_warn[scope] = now
    ngx.log(ngx.WARN, "shared dict write failed (", scope, " ", op, "): ",
        tostring(err), " — data loss possible until dict pressure clears")
end

--- set() with failure logging.
-- @return boolean ok
function _M.set(dict, scope, key, value, ttl)
    local ok, err = dict:set(key, value, ttl)
    if not ok then
        _M.write_failed(scope, "set", err)
    end
    return ok
end

--- incr() with failure logging.
-- @return ok, new value or nil
function _M.incr(dict, scope, key, value, init, ttl)
    local ok, err = dict:incr(key, value, init, ttl)
    if not ok then
        _M.write_failed(scope, "incr", err)
    end
    return ok, err
end

return _M
