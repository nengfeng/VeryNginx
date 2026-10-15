-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : observability - trace, plugin timing, health status

local _M = {}
local json = require "dkjson"

function _M.init()
    -- Collect from worker 0 only (§1.4): init() runs in every worker, and
    -- without this guard an N-worker deployment ran the same 60s stats
    -- collection N times in parallel (shared-dict reads + disk I/O).
    if ngx.worker.id() ~= 0 then
        return
    end
    -- Register worker-level state collection timer (every 60 seconds)
    ngx.timer.every(60, function()
        _M._collect_worker_stats()
        _M._collect_ip_reputation_stats()
        _M._collect_waf_rule_stats()
    end)
end

--- Collect worker-level statistics and expose as metrics.
function _M._collect_worker_stats()
    local metrics = require "core.metrics"

    -- Connection metrics are not available from timer context;
    -- they are exposed via the /status API endpoint during request processing.
    -- Shared dict usage.
    --
    -- The percentage alone is not actionable, and has been misread twice on
    -- this host. capacity()-free_space() reports the slab pool, and the pool is
    -- sized by the worst traffic the dict has ever seen: ip_reputation read
    -- 99.9% of 16 MB while holding 114 keys — about 140 KB per key, which is
    -- not a quantity that can exist — and an nginx restart drops the figure to
    -- 0.7% without a single real entry changing.
    --
    -- So the key count is exported beside it. A percentage can then be checked
    -- rather than believed: 99.9% with 114 keys is a large pool, not a full
    -- dict, and no threshold should fire on it.
    --
    -- One decimal place instead of a floored integer: flooring turned a real
    -- 0.7% into "0%", which made a live dict look like an empty one.
    local shared_dicts = {"vn_config", "vn_locks", "vn_rate_limit", "vn_session",
                          "statistics", "metrics", "metrics_labeled", "healthcheck",
                          "dns_cache", "frequency_limit", "ip_reputation"}
    for _, name in ipairs(shared_dicts) do
        local shared = ngx.shared[name]
        if shared then
            local capacity = shared:capacity()
            local free_space = shared:free_space()
            local used = capacity - free_space
            if capacity > 0 then
                local pct = math.floor((used / capacity) * 1000) / 10
                metrics.gauge("shared_dict_usage_pct", pct, { dict = name })
                metrics.gauge("shared_dict_usage_bytes", used, { dict = name })
                metrics.gauge("shared_dict_capacity_bytes", capacity, { dict = name })
                -- Sampled, not a census: get_keys() returns at most 1024 keys.
                -- Enough to tell a real population from a handful.
                local okk, keys = pcall(function() return shared:get_keys(0) end)
                local n = (okk and type(keys) == "table") and #keys or -1
                metrics.gauge("shared_dict_keys", n, { dict = name })
            end
        end
    end
end

--- Collect IP reputation metrics.
function _M._collect_ip_reputation_stats()
    local metrics = require "core.metrics"
    local ok, ip_rep = pcall(require, "core.ip_reputation")
    if not ok or not ip_rep then return end

    local stats = ip_rep.get_stats()
    metrics.gauge("ip_reputation_flagged_total", stats.flagged or 0, {})
    metrics.gauge("ip_reputation_pending_total", stats.pending or 0, {})
    metrics.gauge("ip_reputation_flagged_today", stats.flagged_today or 0, {})

    -- Top scored IPs (limited cardinality: top 5)
    -- Fast path: check score cache for all flagged IPs (1 shared get each).
    -- Only compute full score (sum_slots = 5 shared gets) for cache misses.
    local flagged = ip_rep.list_flagged()
    local scored = {}
    local s = ngx.shared.ip_reputation
    if s then
        for _, entry in ipairs(flagged) do
            if entry.ip then
                local cached = s:get("ip_rep:score_cache:" .. entry.ip)
                if cached ~= nil then
                    -- Cache hit: use cached score directly
                    if cached > 0 then
                        scored[#scored + 1] = { ip = entry.ip, score = cached }
                    end
                else
                    -- Cache miss: compute full score (cold path, but rare for active IPs)
                    local full_score = ip_rep.get_score(entry.ip)
                    if full_score and full_score > 0 then
                        scored[#scored + 1] = { ip = entry.ip, score = full_score }
                    end
                end
            end
        end
    end
    table.sort(scored, function(a, b) return a.score > b.score end)
    for i = 1, math.min(5, #scored) do
        metrics.gauge("ip_reputation_score", scored[i].score, { ip = scored[i].ip })
    end
end

--- Collect per-rule WAF metrics for Prometheus.
function _M._collect_waf_rule_stats()
    local metrics = require "core.metrics"
    local shared = ngx.shared.vn_config
    if not shared then return end

    local waf_manager = require "waf-rule-manager"
    local rules_obj = waf_manager.load_rules()
    local rules = rules_obj and rules_obj.rules or {}
    local rule_meta = {}
    for _, r in ipairs(rules) do
        rule_meta[r.id] = { category = r.category or "", action = r.action or "log", name = r.name or "" }
    end

    -- Use index instead of get_keys(200) to avoid 200-key ceiling and O(N) scan
    local STATS_INDEX_KEY = "waf_rule_stats:index"
    local idx_raw = shared:get(STATS_INDEX_KEY)
    if not idx_raw then return end

    for rule_id in idx_raw:gmatch("([^\n]+)") do
        if rule_id ~= "" then
            local meta = rule_meta[rule_id] or { category = "", action = "log", name = rule_id }
            local data = shared:get("waf_rule_stats:" .. rule_id)
            if data then
                local ok, stat = pcall(json.decode, data)
                if ok and stat then
                    metrics.gauge("waf_rule_hits_total", stat.hit_count or 0,
                        { rule_id = rule_id, category = meta.category, action = meta.action })
                    metrics.gauge("waf_rule_blocks_total", stat.block_count or 0,
                        { rule_id = rule_id, category = meta.category, action = meta.action })
                    metrics.gauge("waf_rule_challenges_total", stat.challenge_count or 0,
                        { rule_id = rule_id, category = meta.category, action = meta.action })
                end
            end
        end
    end
end

function _M.start_plugin_timer(ctx, plugin_name)
    if ctx and ctx.set_data then
        ctx.set_data(ctx, "timing:" .. plugin_name, ngx.now())
    end
end

function _M.finish_plugin_timer(ctx, plugin_name)
    if not ctx or not ctx.get_data then
        return
    end
    local start = ctx.get_data(ctx, "timing:" .. plugin_name)
    if start then
        local metrics = require "core.metrics"
        metrics.observe("plugin_duration_seconds", ngx.now() - start, { plugin = plugin_name })
    end
end

function _M.export_prometheus()
    local metrics = require "core.metrics"
    return metrics.export_prometheus()
end

return _M