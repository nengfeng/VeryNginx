-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : observability - trace, plugin timing, health status

local _M = {}
local json = require "dkjson"

function _M.init()
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
    -- Shared dict usage (approximate)
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
                local pct = math.floor((used / capacity) * 100)
                metrics.gauge("shared_dict_usage_pct", pct, { dict = name })
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
    local flagged = ip_rep.list_flagged()
    local scored = {}
    for _, entry in ipairs(flagged) do
        if entry.ip then
            local s = ip_rep.get_score(entry.ip)
            if s and s > 0 then
                scored[#scored + 1] = { ip = entry.ip, score = s }
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

    local keys = shared:get_keys(200)
    for _, k in ipairs(keys) do
        if k:sub(1, 15) == "waf_rule_stats:" then
            local rule_id = k:sub(16)
            local meta = rule_meta[rule_id] or { category = "", action = "log", name = rule_id }
            local data = shared:get(k)
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