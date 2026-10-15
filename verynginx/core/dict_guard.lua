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

--- Record a write that succeeded only by evicting someone else.
--
-- This is the failure mode `lua_shared_dict` cannot be configured away from:
-- the directive takes exactly <name> <size> — there is no evict/noevict/slab
-- policy argument (the upstream README documents two arguments, and this
-- build rejects a third). So a full dict cannot be made to refuse writes.
--
-- What it does instead is evict internally and report SUCCESS: ngx.shared.DICT
-- removes other items by LRU until the new one fits, and LRU takes priority
-- over expiration, so even items that are nearly expired get dropped first.
-- The third return value is the only signal that this happened —
--
--     local ok, err, forcible = dict:set(key, value, ttl)
--
-- A plain `if not ok` check never sees it. For a rate-limit counter or a
-- reputation score, a forcible write means some other key's data is gone, and
-- the caller would otherwise never learn about it.
--
-- @param scope string: logical owner
-- @param op string: "set" | "incr" | "add"
function _M.evicted_other(scope, op)
    local now = ngx.now()
    local last = last_warn[scope]
    if last and (now - last) < WARN_INTERVAL then
        return
    end
    last_warn[scope] = now
    ngx.log(ngx.WARN, "shared dict write forced eviction (", scope, " ", op,
        "): no allocatable space, so this write evicted other entries by LRU ",
        "(LRU outranks expiry) — the dict is at its high-water mark; ",
        "check shared_dict_keys and consider a larger zone")
end

--- set() with failure and forced-eviction logging.
-- @return boolean ok: false only on a hard failure (e.g. "no memory")
function _M.set(dict, scope, key, value, ttl)
    local ok, err, forcible = dict:set(key, value, ttl)
    if not ok then
        _M.write_failed(scope, "set", err)
    elseif forcible then
        _M.evicted_other(scope, "set")
    end
    return ok
end

--- incr() with failure and forced-eviction logging.
-- @return ok, err, forcible: as ngx.shared.DICT:incr returns them
function _M.incr(dict, scope, key, value, init, ttl)
    local ok, err, forcible = dict:incr(key, value, init, ttl)
    if not ok then
        _M.write_failed(scope, "incr", err)
    elseif forcible then
        _M.evicted_other(scope, "incr")
    end
    return ok, err, forcible
end

return _M
