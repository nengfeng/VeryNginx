-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : WAF stats controller - test, test-history, stats, hits, timeline, analytics

local _M = {}

local json = require "dkjson"
local waf_manager = require "waf-rule-manager"
local helpers = require "api.helpers"

-- Store test result in ring buffer (max 20 entries)
local function save_test_history(entry)
    local shared = ngx.shared.vn_config
    if not shared then return end
    local idx = (shared:incr("waf_test_history:idx", 1, 0) - 1) % 20 + 1
    shared:set("waf_test_history:data:" .. idx, json.encode(entry), 86400 * 7)
end

--- POST /waf/rules/test - test a rule against test cases
local function handle_test_waf_rule()
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or #raw == 0 then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end
    local ok, body = pcall(json.decode, raw)
    if not ok or type(body) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid JSON" })
    end
    if not body.rule then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "rule is required" })
    end
    if not body.test_cases or type(body.test_cases) ~= "table" or #body.test_cases == 0 then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "test_cases is required" })
    end
    -- Cap test-case count so a single request cannot exhaust the worker CPU
    -- running an unbounded number of regex evaluations.
    if #body.test_cases > 200 then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "test_cases exceeds max of 200" })
    end
    local results = waf_manager.test_rule(body.rule, body.test_cases)
    local passed = 0
    local failed = 0
    for _, r in ipairs(results) do
        if r.passed then
            passed = passed + 1
        else
            failed = failed + 1
        end
    end
    -- Save to test history (keep last 20)
    local test_entry = {
        timestamp = ngx.time(),
        rule_name = body.rule.name or body.rule.id or "unnamed",
        total = #results,
        passed = passed,
        failed = failed,
        results = results,
    }
    save_test_history(test_entry)

    return json.encode({
        ret = "success",
        data = {
            total = #results,
            passed = passed,
            failed = failed,
            results = results
        }
    })
end

--- GET /waf/test-history - retrieve recent test results
local function handle_test_history()
    local shared = ngx.shared.vn_config
    local history = {}
    if shared then
        for i = 1, 20 do
            local data = shared:get("waf_test_history:data:" .. i)
            if data then
                local ok, entry = pcall(json.decode, data)
                if ok then
                    history[#history + 1] = entry
                end
            end
        end
    end
    -- Sort by timestamp descending
    table.sort(history, function(a, b) return (a.timestamp or 0) > (b.timestamp or 0) end)
    return json.encode({ ret = "success", data = history })
end

--- DELETE /waf/test-history - clear test history
local function handle_clear_test_history()
    local shared = ngx.shared.vn_config
    if shared then
        shared:delete("waf_test_history:idx")
        for i = 1, 20 do
            shared:delete("waf_test_history:data:" .. i)
        end
    end
    return json.encode({ ret = "success" })
end

--- GET /waf/stats - get aggregate WAF statistics
local function handle_waf_stats()
    local rules_obj = waf_manager.load_rules()
    local rules = (rules_obj and rules_obj.rules) or {}
    local shared = ngx.shared.vn_config

    local total_rules = #rules
    local enabled_rules = 0
    local by_category = {}
    local by_severity = {}
    local total_hits = 0
    local today_start = math.floor(ngx.time() / 86400) * 86400
    local today_hits = 0
    local top_rules = {}

    for _, r in ipairs(rules) do
        if r.enable ~= false then
            enabled_rules = enabled_rules + 1
        end

        -- Category aggregation
        if not by_category[r.category] then
            by_category[r.category] = { rules = 0, hits = 0 }
        end
        by_category[r.category].rules = by_category[r.category].rules + 1

        -- Severity aggregation
        if not by_severity[r.severity] then
            by_severity[r.severity] = { rules = 0, hits = 0 }
        end
        by_severity[r.severity].rules = by_severity[r.severity].rules + 1

        -- Read runtime stats from shared dict
        local hits = 0
        local last_ts = 0
        if shared then
            local stats_json = shared:get("waf_rule_stats:" .. r.id)
            if stats_json then
                local ok, stats = pcall(json.decode, stats_json)
                if ok and stats then
                    hits = stats.hit_count or 0
                    last_ts = stats.last_triggered or 0
                    r.hit_count = hits
                    r.last_triggered = last_ts
                end
            end
        end

        total_hits = total_hits + hits
        by_category[r.category].hits = by_category[r.category].hits + hits
        by_severity[r.severity].hits = by_severity[r.severity].hits + hits

        -- Today's hits come from the dedicated daily counter (TTL 48h) that
        -- record_hit increments per hit. Falling back to the rule's ALL-TIME
        -- hit_count whenever last_triggered is inside today inflated the
        -- number by tens of thousands on old busy rules.
        local today_key = "waf_rule_stats:" .. r.id .. ":today:" .. os.date("!%Y%m%d", today_start)
        local daily = tonumber(shared:get(today_key)) or 0
        today_hits = today_hits + daily

        -- Build top rules list
        top_rules[#top_rules + 1] = { id = r.id, name = r.name, hits = hits }
    end

    -- Sort top rules by hits descending
    table.sort(top_rules, function(a, b) return a.hits > b.hits end)
    if #top_rules > 10 then
        local top10 = {}
        for i = 1, 10 do
            top10[i] = top_rules[i]
        end
        top_rules = top10
    end

    return json.encode({
        ret = "success",
        data = {
            total_rules = total_rules,
            enabled_rules = enabled_rules,
            total_hits = total_hits,
            today_hits = today_hits,
            by_category = by_category,
            by_severity = by_severity,
            top_rules = top_rules
        }
    })
end

--- GET /waf/stats/:id - get stats for a single rule
local function handle_waf_rule_stats()
    local rule_id = ngx.ctx.waf_rule_id
    if not rule_id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "rule id required" })
    end
    local shared = ngx.shared.vn_config
    local stats = {}
    if shared then
        local stats_json = shared:get("waf_rule_stats:" .. rule_id)
        if stats_json then
            local ok, decoded = pcall(json.decode, stats_json)
            if ok then stats = decoded end
        end
    end
    return json.encode({ ret = "success", data = stats })
end

--- GET /waf/hits - recent WAF hit records
local function handle_list_waf_hits()
    local limit = tonumber(ngx.var.arg_limit) or 50
    if limit > 200 then limit = 200 end
    local hits = waf_manager.get_recent_hits(limit)
    return json.encode({ ret = "success", data = hits })
end

--- GET /waf/hits/by-ip - all recent hits from a specific IP
local function handle_waf_hits_by_ip()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    if not helpers.is_valid_ip(ip) then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid IP address" })
    end
    local shared = ngx.shared.vn_config
    local hits = {}
    if shared then
        for ri = 1, 100 do
            local d = shared:get("waf_recent_hits:data:" .. ri)
            if d then
                local ok, det = pcall(json.decode, d)
                if ok and det.ip == ip then
                    hits[#hits + 1] = det
                end
            end
        end
    end
    table.sort(hits, function(a, b) return (a.timestamp or 0) > (b.timestamp or 0) end)
    return json.encode({ ret = "success", data = hits })
end

--- GET /waf/hits/:idx - full hit detail for drill-down
local function handle_waf_hit_detail()
    local idx = ngx.ctx.waf_rule_id
    if not idx then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "hit index required" })
    end
    local shared = ngx.shared.vn_config
    local detail_json
    if shared then
        detail_json = shared:get("waf_recent_hits:data:" .. idx)
    end
    if not detail_json then
        ngx.status = 404
        return json.encode({ ret = "failed", message = "hit detail not found" })
    end
    local ok, detail = pcall(json.decode, detail_json)
    if not ok then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "corrupted detail data" })
    end

    -- Enrich with rule metadata and IP reputation
    local rules_obj = waf_manager.load_rules()
    if rules_obj and rules_obj.rules then
        for _, r in ipairs(rules_obj.rules) do
            if r.id == detail.rule_id then
                detail.rule_name = r.name or r.id
                detail.rule_category = r.category or ""
                detail.rule_severity = r.severity or ""
                break
            end
        end
    end

    -- Add IP reputation info
    local rep = require "core.ip_reputation"
    detail.ip_score = rep.get_score(detail.ip)
    detail.ip_flagged = rep.is_flagged(detail.ip)
    detail.ip_whitelisted = rep.is_whitelisted(detail.ip)

    -- Count other hits from same IP
    detail.ip_hit_count = 0
    if shared then
        for ri = 1, 100 do
            local d = shared:get("waf_recent_hits:data:" .. ri)
            if d then
                local ok2, det = pcall(json.decode, d)
                if ok2 and det.ip == detail.ip then
                    detail.ip_hit_count = detail.ip_hit_count + 1
                end
            end
        end
    end

    return json.encode({ ret = "success", data = detail })
end

--- GET /waf/timeline - attack timeline aggregated by time bucket + category
local function handle_waf_timeline()
    local bucket_minutes = tonumber(ngx.var.arg_bucket) or 5
    if bucket_minutes < 1 then bucket_minutes = 1 end
    if bucket_minutes > 60 then bucket_minutes = 60 end
    local hours = tonumber(ngx.var.arg_hours) or 1
    if hours < 1 then hours = 1 end
    if hours > 24 then hours = 24 end

    local shared = ngx.shared.vn_config
    if not shared then
        return json.encode({ ret = "success", data = {} })
    end

    local now = ngx.time()
    local window_start = now - (hours * 3600)
    local bucket_seconds = bucket_minutes * 60
    local num_buckets = math.ceil((hours * 3600) / bucket_seconds)

    -- Build rule_id -> category mapping
    local rules_obj = waf_manager.load_rules()
    local rule_cat = {}
    if rules_obj and rules_obj.rules then
        for _, r in ipairs(rules_obj.rules) do
            rule_cat[r.id] = r.category or "other"
        end
    end

    -- Aggregate hits into buckets
    local buckets = {}
    for i = 0, num_buckets - 1 do
        buckets[i] = { start = window_start + i * bucket_seconds, counts = {} }
    end

    for ri = 1, 100 do
        local data = shared:get("waf_recent_hits:data:" .. ri)
        if data then
            local ok, det = pcall(json.decode, data)
            if ok and det and det.action == "block" then
                local ts = det.timestamp or 0
                if ts >= window_start and det.rule_id then
                    local bucket_idx = math.floor((ts - window_start) / bucket_seconds)
                    if bucket_idx >= 0 and bucket_idx < num_buckets then
                        local cat = rule_cat[det.rule_id] or "other"
                        local bucket = buckets[bucket_idx]
                        bucket.counts[cat] = (bucket.counts[cat] or 0) + 1
                    end
                end
            end
        end
    end

    -- Format response
    local result = {}
    for i = 0, num_buckets - 1 do
        local b = buckets[i]
        result[#result + 1] = {
            time = b.start,
            counts = b.counts,
        }
    end

    return json.encode({ ret = "success", data = {
        buckets = result,
        bucket_minutes = bucket_minutes,
        hours = hours,
        categories = (function()
            local cats = {}
            for _, c in pairs(rule_cat) do cats[c] = true end
            local list = {}
            for c in pairs(cats) do list[#list + 1] = c end
            return list
        end)(),
    }})
end

--- GET /waf/analytics - rule effectiveness scoring + dead rule detection
local function handle_waf_analytics()
    local shared = ngx.shared.vn_config
    if not shared then
        return json.encode({ ret = "success", data = { rules = {}, dead_rules = {} } })
    end
    local rules_obj = waf_manager.load_rules()
    local rules = {}
    if rules_obj and rules_obj.rules then
        rules = rules_obj.rules
    end

    local now = ngx.time()
    local thirty_days = 30 * 86400
    local analytics = {}
    local dead_rules = {}

    for _, rule in ipairs(rules) do
        local stat_json = shared:get("waf_rule_stats:" .. rule.id)
        local stat = {}
        if stat_json then
            local ok, decoded = pcall(json.decode, stat_json)
            if ok then stat = decoded end
        end

        local hits = stat.hit_count or 0
        local blocks = stat.block_count or 0
        local challenges = stat.challenge_count or 0
        local last_triggered = stat.last_triggered or 0

        -- Challenge pass count
        local passes = tonumber(shared:get("waf_rule_challenge_pass:" .. rule.id) or 0)

        -- Calculate challenge pass rate
        local pass_rate = "-"
        if challenges > 0 then
            pass_rate = string.format("%.0f%%", (passes / challenges) * 100)
        end

        -- Effectiveness grade (A+/A/B/C/D)
        local grade = "N/A"
        if hits > 0 then
            if challenges > 0 then
                -- Challenge-based: high pass rate = possible false positives
                local ratio = passes / challenges
                if ratio >= 0.8 then grade = "C"
                elseif ratio >= 0.5 then grade = "B"
                else grade = "A"
                end
            elseif blocks == hits then
                -- Always blocks: check if any user recovery
                grade = "A+"
            else
                grade = "B"
            end
        end

        -- Dead rule: 30 days since last hit
        local is_dead = false
        if last_triggered > 0 and (now - last_triggered) > thirty_days then
            is_dead = true
            dead_rules[#dead_rules + 1] = { id = rule.id, name = rule.name, enable = rule.enable,
                                             last_triggered = last_triggered, hits = hits }
        elseif last_triggered == 0 and #rules > 0 then
            local rule_age = now - (rule._created or now)
            if rule_age > thirty_days then
                is_dead = true
                dead_rules[#dead_rules + 1] = { id = rule.id, name = rule.name, enable = rule.enable,
                                                 last_triggered = 0, hits = 0 }
            end
        end

        analytics[#analytics + 1] = {
            id = rule.id,
            name = rule.name,
            enable = rule.enable,
            action = rule.action or "log",
            hits = hits,
            blocks = blocks,
            challenges = challenges,
            challenge_passes = passes,
            challenge_pass_rate = pass_rate,
            last_triggered = last_triggered,
            last_triggered_ago = last_triggered > 0 and (now - last_triggered) or nil,
            grade = grade,
            dead = is_dead,
        }
    end

    return json.encode({ ret = "success", data = { rules = analytics, dead_rules = dead_rules } })
end

function _M.register(api)
    api.register("POST",   "/waf/rules/test",     handle_test_waf_rule,      true)
    api.register("GET",    "/waf/stats",          handle_waf_stats,          true)
    api.register("GET",    "/waf/stats/:id",      handle_waf_rule_stats,     true)
    api.register("GET",    "/waf/hits",           handle_list_waf_hits,      true)
    api.register("GET",    "/waf/hits/by-ip",     handle_waf_hits_by_ip,     true)
    api.register("GET",    "/waf/hits/:id",       handle_waf_hit_detail,     true)
    api.register("GET",    "/waf/timeline",       handle_waf_timeline,       true)
    api.register("GET",    "/waf/test-history",   handle_test_history,       true)
    api.register("DELETE", "/waf/test-history",   handle_clear_test_history, true)
    api.register("GET",    "/waf/analytics",      handle_waf_analytics,      true)
end

return _M
