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
        nameservers = c.nameservers or DEFAULTS.nameservers,
    }
end

-- Read nameservers from /etc/resolv.conf
-- Returns array of IP strings, or nil if unavailable
local function get_system_nameservers()
    local f = io.open("/etc/resolv.conf", "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    if not content then return nil end
    local servers = {}
    for line in content:gmatch("[^\r\n]+") do
        local ip = line:match("^nameserver%s+(%S+)")
        if ip then
            servers[#servers + 1] = ip
        end
    end
    if #servers > 0 then return servers end
    return nil
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
--- Classify an IPv4/IPv6 literal as a private/internal address.
local function is_private_ip(ip)
    if not ip then return false end
    ip = ip:lower()
    -- ::ffff:<IPv4> is an IPv4-mapped IPv6 address. A URL like
    -- https://[::ffff:10.0.0.1]/ must be classified as internal: check the
    -- embedded IPv4 octets (dotted or hex form) before falling through to the IPv6
    -- checks, otherwise it bypasses every IPv4 pattern.
    local mapped = ip:match("^::ffff:(.+)$")
    if mapped then
        -- Try dotted decimal first
        if mapped:match("^%d+%.%d+%.%d+%.%d+$") then
            return is_private_ip(mapped)
        end
        -- Try hex form (e.g., 0a00:1 or 0a00:0001 for 10.0.0.1)
        local hex_parts = {}
        for part in mapped:gmatch("[^:]+") do
            hex_parts[#hex_parts + 1] = part
        end
        if #hex_parts >= 2 then
            -- Last two 16-bit parts form the IPv4 address
            local high = tonumber(hex_parts[#hex_parts - 1], 16)
            local low = tonumber(hex_parts[#hex_parts], 16)
            if high and low then
                local a = math.floor(high / 256)
                local b = high % 256
                local c = math.floor(low / 256)
                local d = low % 256
                local dotted = string.format("%d.%d.%d.%d", a, b, c, d)
                return is_private_ip(dotted)
            end
        end
    end
    -- IPv4 private / reserved
    if ip:match("^10%.") then return true end
    if ip:match("^172%.(1[6-9]%.)") then return true end
    if ip:match("^172%.2%d%.") then return true end
    if ip:match("^172%.3[01]%.") then return true end
    if ip:match("^192%.168%.") then return true end
    if ip:match("^169%.254%.") then return true end
    if ip:match("^127%.") then return true end
    if ip:match("^0%.") then return true end
    if ip == "255.255.255.255" then return true end               -- IPv4 broadcast
    if ip:match("^100%.6[4-9]%.") then return true end           -- CGNAT 100.64.0.0/10
    if ip:match("^100%.[7-9]%d%.") then return true end
    if ip:match("^100%.[1-9]%d%d%.") then return true end
    if ip:match("^2[2-3]%d%.") then return true end              -- multicast 224.0.0.0/4
    -- IPv6 reserved
    if ip == "::" or ip == "0:0:0:0:0:0:0:0" then return true end  -- unspecified
    if ip == "::1" then return true end                             -- loopback
    if ip:match("^fc") or ip:match("^fd") then return true end    -- ULA
    if ip:match("^fe[89ab][0-9a-f]:") then return true end        -- link-local (fe80::/10)
    return false
end

--- Resolve a hostname and report whether any A/AAAA answer is private.
-- @return boolean|nil, string: true=encloses private IP, false=all public,
--   nil=resolver unavailable (caller falls back to fail-closed: deny).
local function resolves_to_private(host)
    -- Cosockets are FORBIDDEN outside request-ish contexts: init_by_lua has
    -- no request, and resty.dns.resolver:new() raises "no request found"
    -- there. A domain-shaped webhook in config.json therefore bricked the
    -- entire nginx start (load_from_file -> validate_config runs at init).
    -- Guard by phase AND wrap everything in pcall so any failure degrades to
    -- "unavailable" instead of raising.
    if ngx.get_phase then
        local ph = ngx.get_phase()
        if ph == "init" or ph == "init_worker" then
            return nil, "phase:" .. tostring(ph)
        end
    end
    local ok_mod, dns_mod = pcall(require, "resty.dns.resolver")
    if not ok_mod or type(dns_mod) ~= "table" then return nil end

    -- Get nameservers: config > system resolv.conf > hardcoded fallback
    local c = cfg()
    local nameservers = c.nameservers
    if not nameservers or #nameservers == 0 then
        nameservers = get_system_nameservers()
    end
    if not nameservers or #nameservers == 0 then
        nameservers = { "8.8.8.8", "1.1.1.1" }
    end

    local ok_new, r = pcall(dns_mod.new, dns_mod,
        { nameservers = nameservers, retrans = 1, timeout = 2000 })
    if not ok_new or not r then return nil end
    local ok_query, result = pcall(function()
        for _, qtype in ipairs({ "A", "AAAA" }) do
            local answers = r:query(host, { qtype = qtype })
            if type(answers) == "table" then
                for _, ans in ipairs(answers) do
                    if ans and ans.address and is_private_ip(ans.address) then
                        return true
                    end
                end
            end
        end
        return false
    end)
    if not ok_query then return nil end
    return result
end

local function validate_webhook_url(url)
    if not url or url == "" then return false, "empty URL" end
    -- Only allow https
    if not url:match("^https://") then
        return false, "only https URLs allowed"
    end
    -- Extract hostname
    local host = url:match("^https://([^/]+)")
    if not host then return false, "invalid URL" end

    -- IPv6 bracket literal: [::1] or [::1]:port. Extract the inner address and
    -- check it directly. Without this, "[::1]" is mangled by the port-strip
    -- below into just "[", bypassing every private-IP check (SSRF).
    local ipv6 = host:match("^%[(.-)%]")
    if ipv6 then
        if is_private_ip(ipv6) then return false, "internal IP not allowed" end
        return true
    end

    -- Strip port if present
    host = host:match("^([^:]+)") or host
    -- Block loopback / unspecified directly
    if host == "localhost" or host == "127.0.0.1" or host:match("^127%.") then
        return false, "localhost not allowed"
    end
    -- Literal IPs: verify directly.
    if host:find(":", 1, true) or host:match("^%d+%.%d+%.%d+%.%d+$") then
        if is_private_ip(host) then return false, "internal IP not allowed" end
        return true
    end
    -- Hostname: resolve and reject if it points anywhere internal. This closes
    -- the DNS-rebinding bypass where the literal host string looks public but
    -- actually resolves to a private address.
    local priv, derr = resolves_to_private(host)
    if priv == nil then
        -- Boot path (init/init_worker): cosockets are unavailable there.
        -- Denying would brick nginx startup over a config that only needs
        -- enforcement at SEND time — send_webhook() re-validates WITH DNS
        -- on every dispatch, so defer to that moment.
        if derr and derr:find("phase:", 1, true) then
            return true
        end
        -- Resolver unavailable (e.g. restricted network / unit test): fail-closed.
        -- Deny the webhook to prevent DNS rebinding SSRF bypass.
        ngx.log(ngx.WARN, "alerting: DNS resolution unavailable for webhook host ",
            host, ": ", tostring(derr), " — denying (fail-closed)")
        return false, "DNS resolution unavailable; webhook denied for security"
    end
    if priv then return false, "internal IP not allowed" end
    return true
end

-- Validate a webhook URL without sending. Exposed for testing and as a
-- reusable guard (e.g. config validation) so callers can check SSRF safety
-- without triggering an outbound HTTP request.
function _M.validate_webhook_url(url)
    return validate_webhook_url(url)
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
    local STATS_INDEX_KEY = "waf_rule_stats:index"
    local idx_raw = s:get(STATS_INDEX_KEY)
    local current_hits = {}

    if idx_raw then
        for rule_id in idx_raw:gmatch("([^\n]+)") do
            if rule_id ~= "" then
                local data = s:get("waf_rule_stats:" .. rule_id)
                if data then
                    local ok, stat = pcall(json.decode, data)
                    if ok and stat then
                        current_hits[rule_id] = stat
                    end
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
        -- Use per-day challenge count as both threshold gate and denominator,
        -- matching waf_stats.lua:422. A lifetime denominator made pass_rate
        -- decay toward 0% over time (FP alert almost always fires).
        local today = os.date("!%Y%m%d")
        local challenges = tonumber(s:get("waf_rule_stats:" .. rule_id .. ":chal:" .. today) or 0)
        if challenges >= conf.fp_min_challenges then
            local pass_key = "waf_rule_stats:" .. rule_id .. ":cpass:" .. today
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
                        "statistics", "metrics", "metrics_labeled", "healthcheck", "dns_cache",
                        "frequency_limit", "ip_reputation"}
    for _, name in ipairs(dict_names) do
        local dict = ngx.shared[name]
        if dict then
            local capacity = dict:capacity()
            local free_space = dict:free_space()
            if capacity > 0 then
                local used_pct = math.floor(((capacity - free_space) / capacity) * 100)
                if used_pct >= conf.shared_dict_alert_threshold then
                    fire_alert("shared_dict_high_usage", name, {
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
        local today = os.date("!%Y%m%d")
        local challenges = tonumber(s:get("waf_rule_stats:" .. rule_id .. ":chal:" .. today) or 0)
        if challenges > 0 then
            local passes = tonumber(s:get("waf_rule_stats:" .. rule_id .. ":cpass:" .. today) or 0)
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
