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
-- Index TTL: matched to LABELED_TTL so the whole index expires together in
-- the rare case of a complete quiet period.  Pruning is done per-entry on
-- every write, so this is only a safety net.
local INDEX_TTL = 3600

-- Low-cardinality core metrics live in the `metrics` dict. High-cardinality
-- per-instance series (per-rule gauges, per-IP score) are routed to their own
-- `metrics_labeled` dict so their (unbounded, churn-prone) growth can never
-- crowd core counters/gauges or saturate one shared dict.
local CORE_DICT = "metrics"
local LABELED_DICT = "metrics_labeled"
-- High-cardinality labeled series (per-rule gauges, per-IP score) are churny
-- and unbounded. Giving them a finite TTL lets the shared dict reclaim space
-- once a series goes quiet, instead of a full dict permanently losing every
-- new key (and only restart recovering it). Active series are re-written by the
-- observability collector well within this window, so they persist.
local LABELED_TTL = 3600

local function is_labeled(name)
    return name:match("^waf_rule_") ~= nil
        or name == "ip_reputation_score"
end

local function shared_for(name)
    local labeled = ngx.shared[LABELED_DICT]
    if labeled and is_labeled(name) then return labeled end
    return ngx.shared[CORE_DICT]
end

local random = nil

local function get_random()
    if not random then random = require "core.random" end
    return random
end

-- Rate-limited log + counter for dropped writes (e.g. shared dict "no memory").
-- A dropped metric used to be silently lost; now it is counted in the core
-- dict (bounded cardinality) and logged at most once per window.
local last_drop_log = 0
local DROP_LOG_INTERVAL = 30
local function record_drop(name, err)
    local core = ngx.shared[CORE_DICT]
    if core then
        pcall(function() core:incr("vn_metrics_dropped_total", 1, 0) end)
    end
    local now = ngx.now()
    if now - last_drop_log > DROP_LOG_INTERVAL then
        last_drop_log = now
        ngx.log(ngx.WARN, "metrics: write dropped for ", name, " (", tostring(err),
            ") — shared dict full? check capacity of ", LABELED_DICT)
    end
end

--- Fast, lock-free membership probe. The index stores newline-separated
--- "key:timestamp" tokens; we search for an exact token to avoid substring
--- collisions between label sets.
local function index_contains(s, key)
    local raw = s:get(INDEX_KEY)
    if not raw then return false end
    return raw:find("\n" .. key .. ":", 1, true) ~= nil
end

--- Parse the index string into {key=ts, ...}.  Returns empty table on any
--- decode error (caller treats it as "index absent").
local function index_parse(s)
    local raw = s:get(INDEX_KEY)
    if not raw then return {} end
    local out = {}
    for line in raw:gmatch("[^\n]+") do
        local eq = line:find(":", 1, true)
        if eq then
            local k = line:sub(1, eq - 1)
            local t = tonumber(line:sub(eq + 1))
            if k ~= "" and t then out[k] = t end
        end
    end
    return out
end

--- Compact the index: drop entries whose timestamp is older than `now - max_age`.
--- Called under the lock; the filtered list is written back with the index TTL.
local function index_prune(s, now, max_age)
    local entries = index_parse(s)
    local kept = {}
    local now_str = ""
    for k, ts in pairs(entries) do
        if now - ts <= max_age then
            kept[k] = ts
        end
    end
    -- Rebuild: deterministic order avoids thrashing the string on each write.
    local parts = {}
    for k, ts in pairs(kept) do
        parts[#parts + 1] = k .. ":" .. tostring(ts)
    end
    table.sort(parts)
    if #parts == 0 then
        s:delete(INDEX_KEY)
    else
        local ok, err = s:set(INDEX_KEY, table.concat(parts, "\n") .. "\n", INDEX_TTL)
        if not ok then
            ngx.log(ngx.WARN, "metrics: index prune write failed (", tostring(err),
                ") — index may be inconsistent")
        end
    end
    return kept
end

--- Record a metric key in the index. get_keys(0)/get_keys(N) is capped at
-- ~1024 entries, so per-rule gauges (3 keys per rule) would silently drop the
-- tail for large rule sets. The index gives export_prometheus the full key
-- list regardless of dict size. Only the rare "new key" path takes a lock.
-- Index entries carry per-entry timestamps; every write prunes entries older
-- than the data TTL, keeping the index bounded even under high label churn.
local function index_add(s, key, data_ttl)
    -- Prune expired entries before checking membership; this keeps the index
    -- bounded and is cheap (string scan, no lock).
    index_prune(s, ngx.time(), data_ttl > 0 and data_ttl or INDEX_TTL)
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
        local ts = tostring(ngx.time())
        local raw = s:get(INDEX_KEY) or ""
        local ok_idx, err_idx = s:set(INDEX_KEY, raw .. key .. ":" .. ts .. "\n", INDEX_TTL)
        if not ok_idx then
            ngx.log(ngx.WARN, "metrics: index write failed (", tostring(err_idx),
                ") for ", key, " — metric may not be exported")
        end
    end
    if locks:get(INDEX_LOCK_KEY) == token then
        locks:delete(INDEX_LOCK_KEY)
    end
end

function _M.init()
    for _, dict_name in ipairs({ CORE_DICT, LABELED_DICT }) do
        local shared = ngx.shared[dict_name]
        if shared then
            shared:add(INDEX_KEY, "\n", 0)
        end
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
    local shared = shared_for(name)
    if not shared then return end
    local ttl = is_labeled(name) and LABELED_TTL or 0
    local ok, err = shared:incr(key, value or 1, 0, ttl)
    if not ok then record_drop(name, err) return end
    index_add(shared, key, ttl)
end

function _M.observe(name, value, labels)
    local count_key = _M.key(name .. "_count", labels)
    local sum_key = _M.key(name .. "_sum", labels)
    local shared = shared_for(name)
    if not shared then return end
    local ttl = is_labeled(name) and LABELED_TTL or 0
    local ok1, err1 = shared:incr(count_key, 1, 0, ttl)
    if not ok1 then record_drop(name .. "_count", err1) return end
    local ok2, err2 = shared:incr(sum_key, value, 0, ttl)
    if not ok2 then record_drop(name .. "_sum", err2) return end
    index_add(shared, count_key, ttl)
    index_add(shared, sum_key, ttl)
end

function _M.gauge(name, value, labels)
    local key = _M.key(name, labels)
    local shared = shared_for(name)
    if not shared then return end
    local ttl = is_labeled(name) and LABELED_TTL or 0
    local ok, err = shared:set(key, value, ttl)
    if not ok then record_drop(name, err) return end
    index_add(shared, key, ttl)
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
    shared_dict_usage_bytes = { type = "gauge", help = "Shared dict used bytes" },
    shared_dict_capacity_bytes = { type = "gauge", help = "Shared dict capacity bytes" },
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
    vn_metrics_dropped_total = {
        type = "counter", help = "Metrics dropped due to shared dict capacity errors"
    },
}

--- Emit every indexed sample of one shared dict into the exporters buffers.
local function emit_dict(shared, seen_names, samples, emitted_keys)
    -- Enumerate solely from the maintained index: it is not limited by the
    -- get_keys ~1024-entry ceiling (which also performs poorly on large dicts).
    -- Every write goes through incr/observe/gauge which keeps the index in
    -- sync, so no get_keys union fallback is needed.
    local raw_idx = shared:get(INDEX_KEY)
    if raw_idx then
        for line in raw_idx:gmatch("[^\n]+") do
            -- Index tokens are "key:timestamp"; strip the timestamp suffix.
            local eq = line:find(":", 1, true)
            if not eq then goto continue end
            local key = line:sub(1, eq - 1)
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
            ::continue::
        end
    end
end

--- Export all metrics in Prometheus text format.
function _M.export_prometheus()
    -- Collect all unique metric names seen, unioning both the core and the
    -- labeled dicts (each keeps its own index).
    local seen_names = {}
    local samples = {}
    local emitted_keys = {}

    for _, dict_name in ipairs({ CORE_DICT, LABELED_DICT }) do
        local shared = ngx.shared[dict_name]
        if shared then
            emit_dict(shared, seen_names, samples, emitted_keys)
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