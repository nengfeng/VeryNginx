-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : alerting engine - detect anomalies and send notifications

local _M = {}

local json = require "dkjson"
local metrics = require "core.metrics"
local audit = require "core.audit"

-- Alert state persisted across timer ticks (prev period hit counts)
local ALERT_STATE_KEY = "alerting:state"
local ALERT_COOLDOWN_KEY = "alerting:cooldown"

-- Default configuration
local DEFAULTS = {
    enabled = false,
    webhook_url = "",
    -- Hit rate spike: current period hits > multiplier * previous period hits
    hit_spike_multiplier = 3.0,
    hit_spike_min_hits = 10,        -- minimum hits in current period to evaluate
    -- False positive: challenge pass rate drop
    fp_pass_rate_threshold = 0.3,   -- alert if pass rate drops below this
    fp_min_challenges = 5,          -- minimum challenges in period to evaluate
    -- Unknown attack pattern detection
    unknown_pattern_min_hits = 5,   -- min hits with same pattern to trigger alert
    -- JA3 cross-IP correlation (distributed scanner detection)
    ja3_cross_ip_threshold = 5,   -- min distinct IPs sharing same JA3 to trigger alert
    -- Shared dict capacity
    shared_dict_alert_threshold = 80,  -- alert when dict usage exceeds this percentage
    -- Detection window
    window_seconds = 360,           -- 1 hour evaluation window (6x per day)
}

-- ---------------------------------------------------------------
-- Utility
-- ---------------------------------------------------------------
local function cfg()
    local c = require("core.config").alerting
    if not c then return DEFAULTS end
    return {
        enabled = c.enabled ~= nil and c.enabled or DEFAULTS.enabled,
        webhook_url = c.webhook_url or DEFAULTS.webhook_url,
        hit_spike_multiplier = c.hit_spike_multiplier or DEFAULTS.hit_spike_multiplier,
        hit_spike_min_hits = c.hit_spike_min_hits or DEFAULTS.hit_spike_min_hits,
        fp_pass_rate_threshold = c.fp_pass_rate_threshold or DEFAULTS.fp_pass_rate_threshold,
        fp_min_challenges = c.fp_min_challenges or DEFAULTS.fp_min_challenges,
        shared_dict_alert_threshold = c.shared_dict_alert_threshold or DEFAULTS.shared_dict_alert_threshold,
        window_seconds = c.window_seconds or DEFAULTS.window_seconds,
    }
end

local function shared()
    return ngx.shared.vn_config
end

-- ---------------------------------------------------------------
-- State management (for period-over-period comparison)
-- ---------------------------------------------------------------
local function load_state()
    local s = shared()
    if not s then return {} end
    local raw = s:get(ALERT_STATE_KEY)
    if not raw then return {} end
    local ok, state = pcall(json.decode, raw)
    if not ok or type(state) ~= "table" then return {} end
    return state
end

local function save_state(state)
    local s = shared()
    if not s then return end
    s:set(ALERT_STATE_KEY, json.encode(state), 86400 * 7)
end

local function is_cooldown(key)
    local s = shared()
    if not s then return false end
    local cd = s:get(ALERT_COOLDOWN_KEY .. ":" .. key)
    return cd ~= nil
end

local function set_cooldown(key, ttl)
    local s = shared()
    if not s then return end
    s:set(ALERT_COOLDOWN_KEY .. ":" .. key, ngx.time(), ttl or 3600)
end

-- ---------------------------------------------------------------
-- Webhook URL validation (prevent SSRF)
-- ---------------------------------------------------------------
local function validate_webhook_url(url)
    if not url or url == "" then return false, "empty URL" end
    -- Only allow https
    if not url:match("^https://") then
        return false, "only https URLs allowed"
    end
    -- Extract hostname
    local host = url:match("^https://([^/]+)")
    if not host then return false, "invalid URL" end
    -- Strip port if present
    host = host:match("^([^:]+)") or host
    -- Block localhost
    if host == "localhost" or host == "127.0.0.1" or host:match("^127%.") then
        return false, "localhost not allowed"
    end
    -- Block private IP ranges
    local ip_patterns = {
        "^10%.",
        "^172%.(1[6-9]%.)",
        "^172%.2%d%.",
        "^172%.3[01]%.",
        "^192%.168%.",
        "^169%.254%.",
        "^0%.",
    }
    for _, pat in ipairs(ip_patterns) do
        if host:match(pat) then
            return false, "internal IP not allowed"
        end
    end
    return true
end

-- ---------------------------------------------------------------
-- Webhook notification
-- ---------------------------------------------------------------
local function send_webhook(url, payload)
    if not url or url == "" then return false, "no webhook url" end
    local ok, err = validate_webhook_url(url)
    if not ok then
        ngx.log(ngx.WARN, "alerting: invalid webhook URL: ", err)
        return false, err
    end
    local httpc = require "resty.http".new()
    httpc:set_timeout(5000)
    local res, werr = httpc:request_uri(url, {
        method = "POST",
        body = json.encode(payload),
        headers = { ["Content-Type"] = "application/json" },
    })
    if not res then return false, werr end
    if res.status >= 400 then return false, "HTTP " .. res.status end
    return true
end

local function fire_alert(alert_type, rule_id, detail)
    local conf = cfg()
    if not conf.enabled then return end

    -- Cooldown: one alert per rule+type per window
    local cd_key = alert_type .. ":" .. (rule_id or "global")
    if is_cooldown(cd_key) then return end
    set_cooldown(cd_key, conf.window_seconds * 2)

    local alert = {
        type = alert_type,
        rule_id = rule_id,
        detail = detail,
        timestamp = ngx.time(),
        source = "verynginz-alerting",
    }

    audit.log("alert_fired", alert_type .. " rule=" .. (rule_id or "-"), "-")

    if conf.webhook_url ~= "" then
        local ok, err = send_webhook(conf.webhook_url, alert)
        if not ok then
            ngx.log(ngx.WARN, "alerting: webhook failed: ", err)
        end
    end

    -- Always record as a metric
    metrics.incr("alert_fired_total", 1, { type = alert_type })
end

-- ---------------------------------------------------------------
-- Evaluation logic
-- ---------------------------------------------------------------
function _M.evaluate()
    local conf = cfg()
    if not conf.enabled then return end

    local s = shared()
    if not s then return end

    local state = load_state()
    local now = ngx.time()
    local waf_manager = require "waf-rule-manager"
    local rules_obj = waf_manager.load_rules()
    local rules = rules_obj and rules_obj.rules or {}

    -- Build rule metadata
    local rule_meta = {}
    for _, r in ipairs(rules) do
        rule_meta[r.id] = { category = r.category or "", action = r.action or "log", name = r.name or "" }
    end

    -- Collect current per-rule stats and detect anomalies
    local keys = s:get_keys(200)
    local current_hits = {}

    for _, k in ipairs(keys) do
        if k:sub(1, 16) == "waf_rule_stats:" then
            local rule_id = k:sub(17)
            local data = s:get(k)
            if data then
                local ok, stat = pcall(json.decode, data)
                if ok and stat then
                    current_hits[rule_id] = stat
                end
            end
        end
    end

    -- 1) Hit rate spike detection
    for rule_id, stat in pairs(current_hits) do
        local hits = stat.hit_count or 0
        local prev = state.prev_hits and state.prev_hits[rule_id] or 0

        if hits >= conf.hit_spike_min_hits and prev > 0 then
            local ratio = hits / prev
            if ratio >= conf.hit_spike_multiplier then
                local meta = rule_meta[rule_id] or {}
                fire_alert("hit_rate_spike", rule_id, {
                    current_hits = hits,
                    previous_hits = prev,
                    ratio = math.floor(ratio * 100) / 100,
                    rule_name = meta.name,
                })
            end
        end
    end

    -- 2) False positive rate detection (challenge pass rate drop)
    for rule_id, stat in pairs(current_hits) do
        local challenges = stat.challenge_count or 0
        if challenges >= conf.fp_min_challenges then
            local pass_key = "waf_rule_challenge_pass:" .. rule_id
            local passes = tonumber(s:get(pass_key) or 0)
            local pass_rate = passes / challenges
            if pass_rate < conf.fp_pass_rate_threshold then
                -- Only alert if previous pass rate was higher (means it dropped)
                local prev_rate = state.prev_pass_rate and state.prev_pass_rate[rule_id]
                if prev_rate and prev_rate >= conf.fp_pass_rate_threshold then
                    local meta = rule_meta[rule_id] or {}
                    fire_alert("false_positive_spike", rule_id, {
                        challenge_count = challenges,
                        pass_count = passes,
                        pass_rate = math.floor(pass_rate * 100) / 100,
                        previous_pass_rate = prev_rate,
                        rule_name = meta.name,
                    })
                end
            end
        end
    end

    -- 3) Unknown attack pattern detection
    --    Scan recent blocked hits for URI patterns not seen in the baseline
    local blocked_patterns = _M._collect_blocked_patterns(s)
    local known_patterns = state.known_patterns or {}
    local new_patterns = {}
    for pattern, info in pairs(blocked_patterns) do
        if not known_patterns[pattern] and info.count >= (conf.unknown_pattern_min_hits or 5) then
            new_patterns[pattern] = info
        end
    end
    for pattern, info in pairs(new_patterns) do
        fire_alert("unknown_attack_pattern", nil, {
            pattern = pattern,
            count = info.count,
            sample_uri = info.sample_uri,
            sample_ip = info.sample_ip,
        })
    end
    -- Update known patterns (add new ones, decay old ones)
    for pattern, info in pairs(blocked_patterns) do
        known_patterns[pattern] = { first_seen = info.first_seen, last_seen = now }
    end
    -- Remove patterns not seen in last 24h to prevent unbounded growth
    for p, meta in pairs(known_patterns) do
        if meta.last_seen and (now - meta.last_seen) > 86400 then
            known_patterns[p] = nil
        end
    end

    -- 4) JA3 cross-IP correlation (distributed scanner detection)
    local ja3_ips = _M._collect_ja3_ip_mapping(s)
    for ja3, ips in pairs(ja3_ips) do
        if #ips >= (conf.ja3_cross_ip_threshold or 5) then
            fire_alert("ja3_cross_ip", nil, {
                ja3_hash = ja3,
                ip_count = #ips,
                sample_ips = table.concat({ips[1] or "", ips[2] or "", ips[3] or ""}, ","),
            })
        end
    end

    -- 5) Shared dict capacity monitoring
    local dict_names = {"vn_config", "vn_locks", "vn_rate_limit", "vn_session",
                        "statistics", "metrics", "healthcheck", "dns_cache",
                        "frequency_limit", "ip_reputation"}
    for _, name in ipairs(dict_names) do
        local dict = ngx.shared[name]
        if dict then
            local capacity = dict:capacity()
            local free_space = dict:free_space()
            if capacity > 0 then
                local used_pct = math.floor(((capacity - free_space) / capacity) * 100)
                if used_pct >= conf.shared_dict_alert_threshold then
                    fire_alert("shared_dict_high_usage", nil, {
                        dict = name,
                        usage_pct = used_pct,
                        capacity_kb = math.floor(capacity / 1024),
                        free_kb = math.floor(free_space / 1024),
                    })
                end
            end
        end
    end

    -- Save current state for next comparison
    local new_state = {
        prev_hits = {},
        prev_pass_rate = {},
        known_patterns = known_patterns,
        updated_at = now,
    }
    for rule_id, stat in pairs(current_hits) do
        new_state.prev_hits[rule_id] = stat.hit_count or 0
        local challenges = stat.challenge_count or 0
        if challenges > 0 then
            local pass_key = "waf_rule_challenge_pass:" .. rule_id
            local passes = tonumber(s:get(pass_key) or 0)
            new_state.prev_pass_rate[rule_id] = passes / challenges
        end
    end
    save_state(new_state)
end

-- ---------------------------------------------------------------
-- Pattern collection from recent blocked hits
-- ---------------------------------------------------------------
function _M._collect_blocked_patterns(s)
    local patterns = {}
    for ri = 1, 100 do
        local d = s:get("waf_recent_hits:data:" .. ri)
        if d then
            local ok, detail = pcall(json.decode, d)
            if ok and detail.action == "block" and detail.uri then
                -- Normalize URI: /api/user/123 -> /api/user/:id
                local pattern = _M._normalize_uri(detail.uri)
                if not patterns[pattern] then
                local entry = {
                    count = 0,
                    first_seen = detail.timestamp or 0,
                    sample_uri = detail.uri,
                    sample_ip = detail.ip,
                }
                patterns[pattern] = entry
                end
                local p = patterns[pattern]
                p.count = p.count + 1
                if (detail.timestamp or 0) > (p.first_seen or 0) then
                    p.sample_uri = detail.uri
                    p.sample_ip = detail.ip
                end
            end
        end
    end
    return patterns
end

function _M._normalize_uri(uri)
    -- Replace hex strings, digits, UUIDs with placeholders
    local p = uri:gsub("%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x", ":uuid")
    p = p:gsub("%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x", ":hex")
    p = p:gsub("%d+", ":id")
    return p
end

function _M._collect_ja3_ip_mapping(s)
    local ja3_ips = {}
    local seen = {} -- track unique ip+ja3 combos
    for ri = 1, 100 do
        local d = s:get("waf_recent_hits:data:" .. ri)
        if d then
            local ok, detail = pcall(json.decode, d)
            if ok and detail.ja3_fingerprint and detail.ip then
                local ja3 = detail.ja3_fingerprint
                local ip = detail.ip
                local key = ja3 .. "|" .. ip
                if not seen[key] then
                    seen[key] = true
                    if not ja3_ips[ja3] then ja3_ips[ja3] = {} end
                    ja3_ips[ja3][#ja3_ips[ja3] + 1] = ip
                end
            end
        end
    end
    return ja3_ips
end

-- ---------------------------------------------------------------
-- Initialization (register evaluation timer)
-- ---------------------------------------------------------------
function _M.init()
    if ngx.worker.id() ~= 0 then return end
    local conf = cfg()
    if not conf.enabled then return end
    local interval = math.max(conf.window_seconds, 60)
    ngx.timer.every(interval, function()
        _M.evaluate()
    end)
end

return _M
