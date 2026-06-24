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

--- Parse a Prometheus metric key back into name + labels.
local function parse_key(key)
    local brace_pos = key:find("{")
    if not brace_pos then
        return key, nil
    end
    local name = key:sub(1, brace_pos - 1)
    local labels_str = key:sub(brace_pos + 1, -2)
    local labels = {}
    for part in labels_str:gmatch('([^,]+)') do
        local lk, lv = part:match('^%s*(.-)%s*=%s*"(.-)"%s*$')
        if lk then
            labels[lk] = lv
        end
    end
    return name, labels
end

--- Export all metrics in Prometheus text format.
function _M.export_prometheus()
    local shared = ngx.shared.metrics
    if not shared then
        return "# metrics shared dict not available\n"
    end

    local buf = {}
    table.insert(buf, "# HELP vn_requests_total Total request count\n")
    table.insert(buf, "# TYPE vn_requests_total counter\n")
    table.insert(buf, "# HELP vn_plugin_errors_total Plugin error count\n")
    table.insert(buf, "# TYPE vn_plugin_errors_total counter\n")
    table.insert(buf, "# HELP vn_upstream_healthy Upstream node health (1=healthy, 0=unhealthy)\n")
    table.insert(buf, "# TYPE vn_upstream_healthy gauge\n")

    local cursor = 0
    local chunk_size = 100
    while true do
        local keys, next_cursor = shared:get_keys(cursor, chunk_size)
        if not keys or #keys == 0 then
            break
        end
        for _, key in ipairs(keys) do
            local val = shared:get(key)
            if val then
                local name, labels = parse_key(key)
                local ls = ""
                if labels and next(labels) then
                    local parts = {}
                    for lk, lv in pairs(labels) do
                        table.insert(parts, lk .. "=\"" .. lv .. "\"")
                    end
                    ls = "{" .. table.concat(parts, ",") .. "}"
                end
                table.insert(buf, name .. ls .. " " .. tostring(val) .. "\n")
            end
        end
        if next_cursor == cursor then
            break
        end
        cursor = next_cursor
    end

    return table.concat(buf)
end

return _M