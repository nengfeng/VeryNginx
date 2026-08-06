-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : Prometheus metrics wrapper (counter/histogram/gauge)

local _M = {}

local INDEX_KEY = "__metrics_index"
local INDEX_LOCK_KEY = "metrics:index_lock"
local INDEX_LOCK_TTL = 5
local INDEX_LOCK_SLEEP = 0.002
-- Match the kernel-blocking index lock budget (500×2ms = up to 1s) so a
-- momentarily contended lock cannot silently drop a metric. A dropped index
-- entry makes the metric invisible to the (index-only) exporter.
local INDEX_LOCK_MAX_RETRIES = 500

local random = nil

local function get_random()
    if not random then random = require "core.random" end
    return random
end

--- Fast, lock-free membership probe. The index is a newline-joined list of
-- metric keys, so we search for a newline-delimited exact token to avoid
-- substring collisions between label sets.
local function index_contains(s, key)
    local raw = s:get(INDEX_KEY)
    if not raw then return false end
    return raw:find("\n" .. key .. "\n", 1, true) ~= nil
end

--- Record a metric key in the index. get_keys(0)/get_keys(N) is capped at
-- ~1024 entries, so per-rule gauges (3 keys per rule) would silently drop the
-- tail for large rule sets. The index gives export_prometheus the full key
-- list regardless of dict size. Only the rare "new key" path takes a lock.
local function index_add(s, key)
    if index_contains(s, key) then return end
    local locks = ngx.shared.vn_locks
    if not locks then return end
    local token = get_random().bytes(8)
    local retries = 0
    while not locks:add(INDEX_LOCK_KEY, token, INDEX_LOCK_TTL) do
        retries = retries + 1
        if retries > INDEX_LOCK_MAX_RETRIES then
            -- The metric value was already written; only its index entry is
            -- missing, which would make it invisible to the exporter. Surface
            -- it loudly so the operator knows the metric may be missing.
            ngx.log(ngx.WARN, "metrics: index lock unavailable after ",
                INDEX_LOCK_MAX_RETRIES, " retries; metric key may not be exported: ",
                key)
            return
        end
        ngx.sleep(INDEX_LOCK_SLEEP)
    end
    -- Re-check under the lock; a concurrent writer may have added it already.
    if not index_contains(s, key) then
        local raw = s:get(INDEX_KEY) or ""
        s:set(INDEX_KEY, raw .. key .. "\n", 0)
    end
    if locks:get(INDEX_LOCK_KEY) == token then
        locks:delete(INDEX_LOCK_KEY)
    end
end

function _M.init()
    local shared = ngx.shared.metrics
    if shared then
        shared:add(INDEX_KEY, "\n", 0)
    end
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
    local shared = ngx.shared.metrics
    if not shared then return end
    shared:incr(key, value or 1, 0)
    index_add(shared, key)
end

function _M.observe(name, value, labels)
    local count_key = _M.key(name .. "_count", labels)
    local sum_key = _M.key(name .. "_sum", labels)
    local shared = ngx.shared.metrics
    if not shared then return end
    shared:incr(count_key, 1, 0)
    shared:incr(sum_key, value, 0)
    index_add(shared, count_key)
    index_add(shared, sum_key)
end

function _M.gauge(name, value, labels)
    local key = _M.key(name, labels)
    local shared = ngx.shared.metrics
    if not shared then return end
    shared:set(key, value)
    index_add(shared, key)
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
    -- Escape \" so the pattern doesn't stop at escaped quotes
    labels_str = labels_str:gsub('\\"', '\1')
    for part in labels_str:gmatch('([^,]+)') do
        local lk, lv = part:match('^%s*(.-)%s*=%s*"(.-)"%s*$')
        if lk then
            labels[lk] = lv:gsub('\1', '"')
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
    verynginx_kernel_block_candidates = { type = "gauge", help = "Kernel blocking candidate count" },
    verynginx_kernel_block_installed = { type = "gauge", help = "Kernel blocking installed entry count" },
    verynginx_kernel_block_desired = { type = "gauge", help = "Kernel blocking desired entry count" },
    verynginx_kernel_block_promotion_tokens = { type = "gauge", help = "Kernel blocking enforce promotion tokens" },
    verynginx_kernel_block_degraded = { type = "gauge", help = "Kernel blocking degraded entry count" },
    verynginx_kernel_block_reconcile_drift = { type = "gauge", help = "Kernel blocking reconcile drift count" },
    verynginx_kernel_block_operations_total = { type = "counter", help = "Kernel blocking operations total" },
    verynginx_kernel_block_promotions_total = { type = "counter", help = "Kernel blocking promotions total" },
    verynginx_kernel_block_lifecycle_transitions_total = {
        type = "counter", help = "Kernel blocking lifecycle transitions"
    },
}

--- Export all metrics in Prometheus text format.
function _M.export_prometheus()
    local shared = ngx.shared.metrics
    if not shared then
        return "# metrics shared dict not available\n"
    end

    -- Collect all unique metric names seen.
    -- Enumerate solely from the maintained index: it is not limited by the
    -- get_keys ~1024-entry ceiling (which also performs poorly on large dicts).
    -- Every write goes through incr/observe/gauge which keeps the index in
    -- sync, so no get_keys union fallback is needed.
    local seen_names = {}
    local samples = {}
    local emitted_keys = {}

    local raw_idx = shared:get(INDEX_KEY)
    if raw_idx then
        for key in raw_idx:gmatch("[^\n]+") do
            if not emitted_keys[key] then
                emitted_keys[key] = true
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
        end
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