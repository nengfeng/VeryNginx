-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : Prometheus metrics wrapper (counter/histogram/gauge)

local _M = {}

function _M.init()
    ngx.shared.metrics:add("__metrics_index", "{}", 0)
end

function _M.key(name, labels)
    local k = name
    if labels and next(labels) then
        local parts = {}
        for lk, lv in pairs(labels) do
            table.insert(parts, lk .. "=\"" .. tostring(lv) .. "\"")
        end
        k = k .. "{" .. table.concat(parts, ",") .. "}"
    end
    return k
end

function _M.incr(name, value, labels)
    local key = _M.key(name, labels)
    ngx.shared.metrics:incr(key, value or 1, 0)
end

function _M.observe(name, value, labels)
    _M.incr(name .. "_count", 1, labels)
    _M.incr(name .. "_sum", value, labels)
end

function _M.gauge(name, value, labels)
    ngx.shared.metrics:set(_M.key(name, labels), value)
end

function _M.export_prometheus()
    -- Phase 6: full Prometheus text format export
    return "# metrics not fully implemented yet\n"
end

return _M