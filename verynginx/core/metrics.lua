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

--- Prometheus type registry: auto-declared metric types and descriptions
local METADATA = {
    vn_requests_total = { type = "counter", help = "Total request count" },
    vn_plugin_errors_total = { type = "counter", help = "Plugin error count" },
    vn_upstream_healthy = { type = "gauge", help = "Upstream node health (1=healthy, 0=unhealthy)" },
    nginx_connections_active = { type = "gauge", help = "Active connections" },
    nginx_connections_reading = { type = "gauge", help = "Reading connections" },
    nginx_connections_writing = { type = "gauge", help = "Writing connections" },
    nginx_connections_waiting = { type = "gauge", help = "Waiting connections" },
    shared_dict_usage_pct = { type = "gauge", help = "Shared dict usage percentage" },
    plugin_duration_seconds_count = { type = "counter", help = "Total plugin duration count" },
    plugin_duration_seconds_sum = { type = "counter", help = "Total plugin duration sum" },
}

--- Export all metrics in Prometheus text format.
function _M.export_prometheus()
    local shared = ngx.shared.metrics
    if not shared then
        return "# metrics shared dict not available\n"
    end

    -- Collect all unique metric names seen
    local seen_names = {}
    local samples = {}

    local cursor = 0
    local chunk_size = 100
    while true do
        local keys, next_cursor = shared:get_keys(cursor, chunk_size)
        if not keys or #keys == 0 then
            break
        end
        for _, key in ipairs(keys) do
            if key == "__metrics_index" then
                goto skip
            end
            local val = shared:get(key)
            if val then
                local name, labels = parse_key(key)
                seen_names[name] = true
                local ls = ""
                if labels and next(labels) then
                    local parts = {}
                    for lk, lv in pairs(labels) do
                        table.insert(parts, lk .. "=\"" .. lv .. "\"")
                    end
                    ls = "{" .. table.concat(parts, ",") .. "}"
                end
                table.insert(samples, name .. ls .. " " .. tostring(val) .. "\n")
            end
        end
        ::skip::
        if next_cursor == cursor then
            break
        end
        cursor = next_cursor
    end

    -- Build HELP/TYPE lines for all seen metrics
    local buf = {}
    for name in pairs(seen_names) do
        local meta = METADATA[name]
        if meta then
            table.insert(buf, "# HELP " .. name .. " " .. meta.help .. "\n")
            table.insert(buf, "# TYPE " .. name .. " " .. meta.type .. "\n")
        else
            -- Infer type from name suffix
            local typ = "gauge"
            if name:match("_count$") or name:match("_sum$") or name:match("_total$") or name:match("_errors$") then
                typ = "counter"
            end
            table.insert(buf, "# HELP " .. name .. " Auto-declared metric\n")
            table.insert(buf, "# TYPE " .. name .. " " .. typ .. "\n")
        end
    end

    -- Append samples
    for _, s in ipairs(samples) do
        table.insert(buf, s)
    end

    return table.concat(buf)
end

return _M