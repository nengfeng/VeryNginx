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
-- Webhook notification
-- ---------------------------------------------------------------
local function send_webhook(url, payload)
    if not url or url == "" then return false, "no webhook url" end
    local httpc = require "resty.http".new()
    httpc:set_timeout(5000)
    local res, err = httpc:request_uri(url, {
        method = "POST",
        body = json.encode(payload),
        headers = { ["Content-Type"] = "application/json" },
    })
    if not res then return false, err end
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

    -- Save current state for next comparison
    local new_state = {
        prev_hits = {},
        prev_pass_rate = {},
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
-- Initialization (register evaluation timer)
-- ---------------------------------------------------------------
function _M.init()
    local conf = cfg()
    if not conf.enabled then return end
    local interval = math.max(conf.window_seconds, 60)
    ngx.timer.every(interval, function()
        _M.evaluate()
    end)
end

return _M
