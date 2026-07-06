-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : API route registration and request dispatching

local _M = {}

local config = require "core.config"
local auth = require "api.auth"
local json = require "dkjson"
local util = require "util"
local waf_manager = require "waf-rule-manager"
local audit = require "core.audit"

-- ---------------------------------------------------------------------------
-- Route table: { method, path, auth_required, handler }
-- ---------------------------------------------------------------------------
_M.routes = {}

function _M.register(method, path, handler, auth_required)
    table.insert(_M.routes, {
        method = method,
        path = path,
        auth_required = (auth_required ~= false),
        handler = handler
    })
end

-- ---------------------------------------------------------------------------
-- Default route handlers
-- ---------------------------------------------------------------------------

--- POST /login - authenticate and return session token
local function handle_login()
    local args = util.get_request_args()
    local user = args.user
    local password = args.password
    if not user or not password then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "user and password required" })
    end

    local strategy = auth.strategies[config.auth_strategy or "session"]
    if not strategy then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "auth strategy not available" })
    end

    local ok, result = strategy.login(user, password)
    if not ok then
        ngx.status = 401
        audit.log("login_failed", result, user)
        return json.encode({ ret = "failed", message = result })
    end

    auth.set_session_cookie(result)
    ngx.status = 200
    audit.log("login_success", "", user)
    return json.encode({ ret = "success", token = result })
end

--- POST /logout - revoke current session
local function handle_logout()
    local cookie_obj = require("cookie"):new()
    if cookie_obj then
        local fields = cookie_obj:get_all()
        if fields then
            local prefix = (config and config.cookie_prefix) or "verynginx"
            local token = fields[prefix .. "_session"]
            if token then
                require("core.session").revoke(token)
                audit.log("logout", "")
            end
        end
    end
    -- Clear the cookie regardless
    ngx.header["Set-Cookie"] = ((config and config.cookie_prefix) or "verynginx") .. "_session=; Path=/; Max-Age=0"
    return json.encode({ ret = "success" })
end

--- POST /config - update config
local function handle_set_config()
    -- Rate limit config saves
    local rl = require "api.rate_limit"
    if not rl.allow("config_save:" .. (ngx.var.remote_addr or ""), 30, 60) then
        ngx.status = 429
        return json.encode({ ret = "failed", message = "too many requests" })
    end

    -- Limit request body size to prevent memory exhaustion (DoS)
    local cl = tonumber(ngx.var.content_length) or 0
    if cl > 1048576 then
        ngx.status = 413
        return json.encode({ ret = "failed", message = "request body too large (max 1MB)" })
    end

    ngx.req.read_body()
    local content_type = ngx.var.content_type or ""
    local raw_body = ngx.req.get_body_data()
    if not raw_body or raw_body == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end

    local new_config

    -- Support both JSON body and form-encoded + base64
    if content_type:lower():find("application/json", 1, true) then
        new_config = json.decode(raw_body)
    else
        local args = ngx.req.get_post_args()
        if args and args.config then
            local decoded = ngx.decode_base64(args.config)
            if decoded then
                local unescaped = ngx.unescape_uri(decoded)
                new_config = json.decode(unescaped)
            end
        end
    end

    if not new_config then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid config" })
    end

    local ok, err = require("core.config").save(new_config)
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = err })
    end

    return json.encode({ ret = "success" })
end

--- GET /status - return runtime status
local function handle_get_status()
    local status_info = {
        ret = "success",
        time = ngx.now(),
        connections_active = ngx.var.connections_active,
        connections_reading = ngx.var.connections_reading,
        connections_writing = ngx.var.connections_writing,
        connections_waiting = ngx.var.connections_waiting,
    }
    return json.encode(status_info)
end

--- GET /metrics - return Prometheus metrics
local function handle_get_metrics()
    ngx.header["Content-Type"] = "text/plain; version=0.0.4"
    return require("core.metrics").export_prometheus()
end

--- GET /summary - return request statistics
local function handle_get_summary()
    local args = ngx.req.get_uri_args()
    return require("core.statistics").report(args.type or "short")
end

--- GET /csrf - return a CSRF token (stored in session for later verification)
local function handle_get_csrf()
    local ctx = ngx.ctx.vn_ctx
    if not ctx then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "no request context" })
    end
    local csrf = require "api.csrf"
    local token = csrf.generate(ctx)
    return json.encode({ ret = "success", csrf_token = token })
end

--- GET /config - sanitize config dump (remove password hashes)
local function handle_get_config()
    local raw = require("core.config").report()
    local ok, decoded = pcall(json.decode, raw)
    if ok and decoded and decoded.admin then
        for _, a in ipairs(decoded.admin) do
            a.password_hash = "(redacted)"
        end
    end
    if ok then
        return json.encode(decoded)
    end
    return raw
end

-- ---------------------------------------------------------------------------
-- WAF rule management handlers
-- ---------------------------------------------------------------------------

--- GET /waf/rules - list rules with filtering and pagination
local function handle_list_waf_rules()
    local args = ngx.req.get_uri_args()
    local rules_obj = waf_manager.load_rules()
    local rules = (rules_obj and rules_obj.rules) or {}

    -- Count by category (from full un-filtered rules)
    local categories = {}
    for _, r in ipairs(rules) do
        categories[r.category] = (categories[r.category] or 0) + 1
    end

    -- Filter by category
    local category = args.category
    if category and #category > 0 then
        local filtered = {}
        for _, r in ipairs(rules) do
            if r.category == category then
                filtered[#filtered + 1] = r
            end
        end
        rules = filtered
    end

    -- Filter by severity
    local severity = args.severity
    if severity and #severity > 0 then
        local filtered = {}
        for _, r in ipairs(rules) do
            if r.severity == severity then
                filtered[#filtered + 1] = r
            end
        end
        rules = filtered
    end

    -- Pagination
    local page = tonumber(args.page) or 1
    local limit = tonumber(args.limit) or 20
    if page < 1 then page = 1 end
    if limit < 1 then limit = 20 end
    if limit > 100 then limit = 100 end

    local total = #rules
    local total_pages = math.ceil(total / limit)
    if page > total_pages and total_pages > 0 then page = total_pages end
    local start_idx = (page - 1) * limit + 1
    local end_idx = math.min(start_idx + limit - 1, total)
    local page_rules = {}
    local shared = ngx.shared.vn_config
    for i = start_idx, end_idx do
        local r = rules[i]
        -- Read runtime stats from shared dict
        if shared then
            local stats_json = shared:get("waf_rule_stats:" .. r.id)
            if stats_json then
                local ok, stats = pcall(json.decode, stats_json)
                if ok and stats then
                    r.hit_count = stats.hit_count or r.hit_count
                    r.last_triggered = stats.last_triggered or r.last_triggered
                end
            end
        end
        page_rules[#page_rules + 1] = r
    end

    return json.encode({
        ret = "success",
        data = {
            rules = page_rules,
            pagination = {
                page = page,
                limit = limit,
                total = total,
                total_pages = total_pages
            },
            categories = categories
        }
    })
end

--- POST /waf/rules - create a new rule
local function handle_create_waf_rule()
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or #raw == 0 then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end
    local ok, rule = pcall(json.decode, raw)
    if not ok or type(rule) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid JSON" })
    end
    local ok2, result = waf_manager.create_rule(rule)
    if not ok2 then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(result) })
    end
    audit.log("waf_rule_created", "id=" .. result.id .. " name=" .. result.name)
    return json.encode({
        ret = "success",
        data = {
            id = result.id,
            name = result.name,
            created_at = result.created_at,
            version = result.version
        }
    })
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

-- Store test result in ring buffer (max 20 entries)
function save_test_history(entry)
    local shared = ngx.shared.vn_config
    if not shared then return end
    local idx = (shared:incr("waf_test_history:idx", 1, 0) - 1) % 20 + 1
    shared:set("waf_test_history:data:" .. idx, json.encode(entry), 86400 * 7)
end

-- ============================================================
-- GET /waf/test-history - retrieve recent test results
-- ============================================================
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

-- ============================================================
-- DELETE /waf/test-history - clear test history
-- ============================================================
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

--- POST /waf/rules/reload - force reload rules from file
local function handle_reload_waf_rules()
    local ok, err = waf_manager.reload()
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(err) })
    end
    audit.log("waf_rules_reloaded", "")
    return json.encode({ ret = "success", message = "rules reloaded" })
end

--- GET /waf/rules/history - get change history
local function handle_waf_rule_history()
    local args = ngx.req.get_uri_args()
    local limit = tonumber(args.limit) or 50
    local history = waf_manager.get_history(limit)
    -- Omit full rule_data for list view to reduce payload size
    local slim = {}
    for _, h in ipairs(history) do
        slim[#slim + 1] = {
            version = h.version,
            timestamp = h.timestamp,
            action = h.action,
            rule_count = h.rule_count
        }
    end
    return json.encode({ ret = "success", data = slim })
end

--- POST /waf/rules/rollback - rollback rules to a previous version
local function handle_rollback_waf_rules()
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
    local version = tonumber(body.version)
    if not version then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "version is required" })
    end
    local rule_id = body.rule_id or ""
    local ok2, err = waf_manager.rollback(rule_id, version)
    if not ok2 then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(err) })
    end
    audit.log("waf_rules_rollback", "version=" .. tostring(version))
    return json.encode({ ret = "success", message = "Rolled back to version " .. tostring(version) })
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

        if last_ts >= today_start then
            today_hits = today_hits + hits
        end

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

--- GET /waf/rules/:id - get a single rule
--- PUT /waf/rules/:id - update a rule
--- DELETE /waf/rules/:id - delete a rule
--- POST /waf/rules/:id/enable - enable a rule
--- POST /waf/rules/:id/disable - disable a rule
--- GET /waf/stats/:id - get stats for a single rule
-- These handlers receive the :id via ngx.ctx.waf_rule_id, set by dispatch()

local function handle_get_waf_rule()
    local rule_id = ngx.ctx.waf_rule_id
    if not rule_id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "rule id required" })
    end
    local rules_obj = waf_manager.load_rules()
    local rules = (rules_obj and rules_obj.rules) or {}
    for _, r in ipairs(rules) do
        if r.id == rule_id then
            -- Attach runtime stats to the response
            local shared = ngx.shared.vn_config
            if shared then
                local stats_json = shared:get("waf_rule_stats:" .. r.id)
                if stats_json then
                    local ok, stats = pcall(json.decode, stats_json)
                    if ok and stats then
                        r.hit_count = stats.hit_count or r.hit_count
                        r.last_triggered = stats.last_triggered or r.last_triggered
                    end
                end
            end
            return json.encode({ ret = "success", data = r })
        end
    end
    ngx.status = 404
    return json.encode({ ret = "failed", message = "rule not found" })
end

local function handle_update_waf_rule()
    local rule_id = ngx.ctx.waf_rule_id
    if not rule_id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "rule id required" })
    end
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or #raw == 0 then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end
    local ok, updates = pcall(json.decode, raw)
    if not ok or type(updates) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid JSON" })
    end
    local ok2, result = waf_manager.update_rule(rule_id, updates)
    if not ok2 then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(result) })
    end
    audit.log("waf_rule_updated", "id=" .. rule_id .. " version=" .. result.version)
    return json.encode({ ret = "success",
        data = { id = rule_id, version = result.version, updated_at = result.updated_at } })
end

local function handle_delete_waf_rule()
    local rule_id = ngx.ctx.waf_rule_id
    if not rule_id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "rule id required" })
    end
    local ok, err = waf_manager.delete_rule(rule_id)
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(err) })
    end
    audit.log("waf_rule_deleted", "id=" .. rule_id)
    return json.encode({ ret = "success", message = "rule deleted" })
end

local function handle_enable_waf_rule()
    local rule_id = ngx.ctx.waf_rule_id
    if not rule_id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "rule id required" })
    end
    local ok, result = waf_manager.update_rule(rule_id, { enable = true })
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(result) })
    end
    audit.log("waf_rule_enabled", "id=" .. rule_id)
    return json.encode({ ret = "success", message = "rule enabled" })
end

local function handle_disable_waf_rule()
    local rule_id = ngx.ctx.waf_rule_id
    if not rule_id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "rule id required" })
    end
    local ok, result = waf_manager.update_rule(rule_id, { enable = false })
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(result) })
    end
    audit.log("waf_rule_disabled", "id=" .. rule_id)
    return json.encode({ ret = "success", message = "rule disabled" })
end

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

--- GET /waf/analytics - rule effectiveness scoring + dead rule detection
local function handle_waf_analytics()
    local shared = ngx.shared.vn_config
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

-- ============================================================
-- Rule change staging / approval flow
-- ============================================================

local PENDING_PREFIX = "waf_pending_rule:"

local function util_get_request_args()
    ngx.req.read_body()
    local content_type = ngx.var.content_type or ""
    if content_type:lower():find("application/json", 1, true) then
        local body = ngx.req.get_body_data()
        if body and body ~= "" then
            local ok, parsed = pcall(json.decode, body)
            if ok then return parsed end
        end
    end
    return ngx.req.get_post_args()
end

--- POST /waf/rules/:id/stage — save a rule change as pending (not yet active)
local function handle_stage_waf_rule()
    local rule_id = ngx.ctx.waf_rule_id
    if not rule_id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "rule id required" })
    end
    local shared = ngx.shared.vn_config
    if not shared then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "shared dict not available" })
    end

    local args = util_get_request_args()
    if not args or type(args) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid request body" })
    end

    local pending = {
        rule_id = rule_id,
        staged_at = ngx.time(),
        staged_by = "-",
        proposed = args,
    }
    shared:set(PENDING_PREFIX .. rule_id, json.encode(pending))
    audit.log("rule_staged", rule_id, "-")
    return json.encode({ ret = "success", data = pending })
end

--- POST /waf/rules/:id/confirm — activate a staged rule change
local function handle_confirm_waf_rule()
    local rule_id = ngx.ctx.waf_rule_id
    if not rule_id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "rule id required" })
    end
    local shared = ngx.shared.vn_config
    if not shared then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "shared dict not available" })
    end

    local pending_json = shared:get(PENDING_PREFIX .. rule_id)
    if not pending_json then
        ngx.status = 404
        return json.encode({ ret = "failed", message = "no pending change for this rule" })
    end

    local ok, pending = pcall(json.decode, pending_json)
    if not ok or not pending then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "corrupted pending data" })
    end

    -- Apply the change by updating the actual rule
    local rules_obj = waf_manager.load_rules()
    local rules = rules_obj and rules_obj.rules or {}
    local updated = false
    for _, rule in ipairs(rules) do
        if rule.id == rule_id then
            for k, v in pairs(pending.proposed) do
                if k ~= "id" then
                    rule[k] = v
                end
            end
            updated = true
            break
        end
    end

    if not updated then
        shared:delete(PENDING_PREFIX .. rule_id)
        ngx.status = 404
        return json.encode({ ret = "failed", message = "rule not found" })
    end

    -- Save the updated rules via config
    waf_manager._save_rules_through_config(rules)
    shared:delete(PENDING_PREFIX .. rule_id)
    audit.log("rule_change_confirmed", rule_id, "-")
    return json.encode({ ret = "success", message = "rule change applied" })
end

--- DELETE /waf/rules/:id/pending — discard a staged rule change
local function handle_discard_waf_rule()
    local rule_id = ngx.ctx.waf_rule_id
    if not rule_id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "rule id required" })
    end
    local shared = ngx.shared.vn_config
    if not shared then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "shared dict not available" })
    end

    local existed = shared:get(PENDING_PREFIX .. rule_id) ~= nil
    shared:delete(PENDING_PREFIX .. rule_id)
    if existed then
        audit.log("rule_change_discarded", rule_id, "-")
    end
    local msg = existed and "pending change discarded" or "no pending change"
    return json.encode({ ret = "success", message = msg })
end

--- GET /waf/rules/pending — list all pending rule changes
local function handle_list_pending_rules()
    local shared = ngx.shared.vn_config
    local result = {}
    if shared then
        local keys = shared:get_keys(200)
        for _, k in ipairs(keys) do
            if k:sub(1, #PENDING_PREFIX) == PENDING_PREFIX then
                local data = shared:get(k)
                if data then
                    local ok, decoded = pcall(json.decode, data)
                    if ok and decoded then
                        result[#result + 1] = decoded
                    end
                end
            end
        end
    end
    return json.encode({ ret = "success", data = result })
end

--- GET /upstreams/health - return runtime health status for all upstream nodes
local function handle_get_upstream_health()
    local upstreams_data = {}
    local health_shared = ngx.shared.healthcheck

    for name, upstream in pairs(config and config.backend_upstream or {}) do
        local nodes_status = {}
        for _, node in ipairs(upstream.nodes or {}) do
            local n = { host = node.host, port = node.port }
            if health_shared then
                local sk = "hc:" .. name .. ":" .. node.host .. ":" .. tostring(node.port)
                local state = health_shared:get(sk .. ":state")
                local failures = tonumber(health_shared:get(sk .. ":failures") or 0)
                local last_error = health_shared:get(sk .. ":last_error")
                n.healthy = (state ~= "unhealthy")
                n.failures = failures
                n.last_error = last_error
                local cb_key = "cb:" .. name .. ":" .. node.host .. ":" .. tostring(node.port)
                n.circuit_open = (health_shared:get(cb_key) == "open")
            else
                n.healthy = true
                n.failures = 0
                n.last_error = nil
                n.circuit_open = false
            end
            nodes_status[#nodes_status + 1] = n
        end
        upstreams_data[name] = nodes_status
    end

    return json.encode({ ret = "success", data = upstreams_data })
end

-- ============================================================
-- GET /waf/hits - recent WAF hit records
-- ============================================================
local function handle_list_waf_hits()
    local limit = tonumber(ngx.var.arg_limit) or 50
    if limit > 200 then limit = 200 end
    local hits = waf_manager.get_recent_hits(limit)
    return json.encode({ ret = "success", data = hits })
end

-- ============================================================
-- GET /waf/hits/:idx - full hit detail for drill-down
-- ============================================================
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

-- ============================================================
-- GET /waf/hits/by-ip - all recent hits from a specific IP
-- ============================================================
local function handle_waf_hits_by_ip()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
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

-- ============================================================
-- GET /waf/timeline - attack timeline aggregated by time bucket + category
-- ============================================================
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

-- ============================================================
-- GET /config/export - download config.json
-- ============================================================
local function handle_export_config()
    local path = require("core.config").resolve_path() .. "configs/config.json"
    local f = io.open(path, "r")
    if not f then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "config file not found" })
    end
    local content = f:read("*all")
    f:close()
    ngx.header["content-type"] = "application/json; charset=utf-8"
    ngx.header["content-disposition"] = 'attachment; filename="config.json"'
    return content
end

-- ============================================================
-- POST /config/import - upload config.json
-- ============================================================
local function handle_import_config()
    local cl = tonumber(ngx.var.content_length) or 0
    if cl > 1048576 then
        ngx.status = 413
        return json.encode({ ret = "failed", message = "request body too large" })
    end
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or raw == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "body required" })
    end
    local ok, parsed = pcall(json.decode, raw)
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid json" })
    end
    local ok2, err = require("core.config").save(parsed)
    if not ok2 then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(err) })
    end
    return json.encode({ ret = "success" })
end

-- ============================================================
-- GET /plugins - list registered plugins with enable status
-- ============================================================
local function handle_list_plugins()
    local plugin_mod = require "core.plugin"
    local list = {}
    for _, p in ipairs(plugin_mod.plugins) do
        list[#list + 1] = {
            name = p.name,
            enable = plugin_mod.is_enabled(p),
            priority = p.priority,
            critical = p.critical or false,
            description = p.description or ""
        }
    end
    return json.encode({ ret = "success", data = list })
end

-- ============================================================
-- POST /plugins/:id/toggle - toggle a plugin's enabled state
-- ============================================================
local function handle_toggle_plugin()
    local name = ngx.ctx.waf_rule_id
    if not name or name == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "plugin name required" })
    end
    local config_mod = require "core.config"
    local plugins = config_mod.plugin
    if not plugins[name] then plugins[name] = {} end
    local entry = plugins[name]
    -- Determine current effective state from entry or plugin default
    local current = true
    if entry.enable ~= nil then
        current = entry.enable == true
    else
        local plugin_mod = require "core.plugin"
        for _, p in ipairs(plugin_mod.plugins) do
            if p.name == name then
                current = p.default_enable ~= false
                break
            end
        end
    end
    -- Build a plain save table from config.report(): avoids metatable /
    -- __pairs edge cases in some LuaJIT builds.
    local save_tbl = json.decode(config_mod.report())
    save_tbl.plugin = save_tbl.plugin or {}
    save_tbl.plugin[name] = save_tbl.plugin[name] or {}
    save_tbl.plugin[name].enable = not current
    local ok, err = config_mod.save(save_tbl)
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(err) })
    end
    -- Mirror into live config_data so subsequent reads see the new state
    entry.enable = save_tbl.plugin[name].enable
    return json.encode({ ret = "success", data = { name = name, enable = entry.enable } })
end

-- ============================================================
-- GET /stats/top-paths - top N request paths by count
-- ============================================================
local function handle_top_paths()
    local limit = tonumber(ngx.var.arg_limit) or 20
    if limit > 100 then limit = 100 end
    local stats_mod = require "core.statistics"
    local paths = stats_mod.get_top_paths(limit)
    return json.encode({ ret = "success", data = paths })
end

-- ---------------------------------------------------------------------------
-- Reputation API handlers
-- ---------------------------------------------------------------------------

local function handle_reputation_stats()
    local rep = require "core.ip_reputation"
    local stats = rep.get_stats()
    return json.encode({ ret = "success", data = stats })
end

local function handle_reputation_flagged()
    local rep = require "core.ip_reputation"
    local list = rep.list_flagged()
    return json.encode({ ret = "success", data = list })
end

local function handle_reputation_whitelist()
    local rep = require "core.ip_reputation"
    local list = rep.list_whitelist()
    return json.encode({ ret = "success", data = list })
end

local function handle_reputation_score()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    local rep = require "core.ip_reputation"
    return json.encode({
        ret = "success",
        data = {
            score = rep.get_score(ip),
            flagged = rep.is_flagged(ip),
            pending = rep.has_pending(ip),
            whitelisted = rep.is_whitelisted(ip),
        }
    })
end

local function handle_reputation_clear()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    local rep = require "core.ip_reputation"
    rep.clear_ip(ip)
    return json.encode({ ret = "success" })
end

local function handle_reputation_whitelist_add()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.req.read_body()
        local raw = ngx.req.get_body_data()
        if raw then
            local ok, parsed = pcall(json.decode, raw)
            if ok and parsed then ip = parsed.ip end
        end
    end
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    local rep = require "core.ip_reputation"
    rep.add_whitelist(ip)
    return json.encode({ ret = "success" })
end

local function handle_reputation_whitelist_remove()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    local rep = require "core.ip_reputation"
    rep.remove_whitelist(ip)
    return json.encode({ ret = "success" })
end

local function handle_reputation_persist()
    local rep = require "core.ip_reputation"
    rep.persist()
    return json.encode({ ret = "success" })
end

-- ============================================================
-- GET /audit - recent audit log entries
-- ============================================================
local function handle_get_audit()
    local limit = tonumber(ngx.var.arg_limit) or 200
    if limit > 1000 then limit = 1000 end
    local user_filter = ngx.var.arg_user
    local action_filter = ngx.var.arg_action
    local since_ts = tonumber(ngx.var.arg_since)
    local until_ts = tonumber(ngx.var.arg_until)
    local entries = audit.get_filtered(user_filter, action_filter, since_ts, until_ts, limit)
    return json.encode({ ret = "success", data = entries })
end

-- ============================================================
-- Frequency Limit handlers
-- ============================================================

local function handle_frequency_stats()
    local shared = ngx.shared.frequency_limit
    if not shared then
        return json.encode({ ret = "success", data = {} })
    end
    local keys = shared:get_keys(200)
    local stats = {}
    for _, k in ipairs(keys) do
        if k:sub(1, 3) == "fl:" then
            local val = shared:get(k)
            if val and val > 0 then
                stats[#stats + 1] = { key = k, count = val }
            end
        end
    end
    table.sort(stats, function(a, b) return a.count > b.count end)
    return json.encode({ ret = "success", data = stats })
end

local function handle_frequency_rules()
    local rules = config.rule.frequency_limit or {}
    return json.encode({ ret = "success", data = rules })
end

local function handle_frequency_rule_save()
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or raw == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end
    local ok, rule = pcall(json.decode, raw)
    if not ok or type(rule) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid JSON" })
    end
    if not rule.id or rule.id == "" then
        rule.id = "freq_" .. tostring(ngx.time())
    end
    if not config.rule then config.rule = {} end
    local rules = config.rule.frequency_limit or {}
    local updated = false
    for i, r in ipairs(rules) do
        if r.id == rule.id then
            rules[i] = rule
            updated = true
            break
        end
    end
    if not updated then
        rules[#rules + 1] = rule
    end
    config.rule.frequency_limit = rules
    local cfg_mod = require "core.config"
    cfg_mod.save(cfg_mod)
    audit.log("frequency_rule_saved", rule.id, "-")
    return json.encode({ ret = "success", data = { id = rule.id } })
end

local function handle_frequency_rule_delete()
    local rule_id = ngx.ctx.waf_rule_id
    if not rule_id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "rule id required" })
    end
    local rules = config.rule.frequency_limit or {}
    local filtered = {}
    for _, r in ipairs(rules) do
        if r.id ~= rule_id then
            filtered[#filtered + 1] = r
        end
    end
    if not config.rule then config.rule = {} end
    config.rule.frequency_limit = filtered
    local cfg_mod = require "core.config"
    cfg_mod.save(cfg_mod)
    audit.log("frequency_rule_deleted", rule_id, "-")
    return json.encode({ ret = "success", message = "rule deleted" })
end

-- ============================================================
-- GeoIP handlers
-- ============================================================

local function handle_geoip_lookup()
    local ip = ngx.var.arg_ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip parameter required" })
    end
    local geoip_mod = require "core.geoip"
    local result = geoip_mod.lookup(ip)
    if not result then
        return json.encode({ ret = "success", data = nil, message = "IP not found in GeoIP database" })
    end
    return json.encode({ ret = "success", data = result })
end

local function handle_geoip_stats()
    local geoip_mod = require "core.geoip"
    local stats = geoip_mod.get_stats(ngx.shared.vn_config)
    return json.encode({ ret = "success", data = stats })
end

local function handle_geoip_config()
    local c = require "core.config"
    return json.encode({ ret = "success", data = c.geoip or {} })
end

local function handle_geoip_config_set()
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or raw == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end
    local ok, new_config = pcall(json.decode, raw)
    if not ok or type(new_config) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid JSON" })
    end
    local c = require "core.config"
    local cfg_data = c.report and json.decode(c.report()) or {}
    cfg_data.geoip = new_config
    local cfg_mod = require "core.config"
    cfg_mod.save(cfg_data)
    return json.encode({ ret = "success", message = "GeoIP config updated" })
end

-- ============================================================
-- Fingerprint database handlers
-- ============================================================

local function handle_fingerprint_list()
    local fp = require "core.fingerprint_db"
    fp.reload()
    return json.encode({ ret = "success", data = fp.list() })
end

local function handle_fingerprint_add()
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or raw == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end
    local ok, entry = pcall(json.decode, raw)
    if not ok or type(entry) ~= "table" or not entry.hash or not entry.name then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "hash and name are required" })
    end
    local fp = require "core.fingerprint_db"
    fp.reload()
    fp.add(entry)
    return json.encode({ ret = "success", data = fp.get(entry.hash) })
end

local function handle_fingerprint_update()
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or raw == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end
    local ok, entry = pcall(json.decode, raw)
    if not ok or type(entry) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid JSON" })
    end
    local fp = require "core.fingerprint_db"
    fp.reload()
    if entry.hash then
        fp.add(entry)
    end
    return json.encode({ ret = "success", data = entry.hash and fp.get(entry.hash) or fp.list() })
end

local function handle_fingerprint_delete()
    local hash = ngx.ctx.waf_rule_id
    if not hash then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "fingerprint hash required" })
    end
    local fp = require "core.fingerprint_db"
    fp.reload()
    local removed = fp.remove(hash)
    return json.encode({ ret = "success", removed = removed })
end

local function handle_fingerprint_stats()
    local fp = require "core.fingerprint_db"
    fp.reload()
    return json.encode({ ret = "success", data = { total = #fp.list(), categories = fp.categories() } })
end

-- ============================================================
-- GeoIP auto-updater handlers
-- ============================================================

local function handle_geoip_status()
    local updater = require "core.geoip_updater"
    local status = updater.get_status()
    return json.encode({ ret = "success", data = status })
end

local function handle_geoip_update()
    local updater = require "core.geoip_updater"
    local ok, err, status = updater.check_update()
    if ok then
        return json.encode({ ret = "success", message = err })
    end
    ngx.status = status or 400
    return json.encode({ ret = "failed", message = tostring(err) })
end

-- ---------------------------------------------------------------------------
-- Register default routes
-- ---------------------------------------------------------------------------
_M.register("POST", "/login", handle_login, false)
_M.register("POST", "/logout", handle_logout, true)
_M.register("GET", "/config", handle_get_config, true)
_M.register("POST", "/config", handle_set_config, true)
_M.register("GET", "/status", handle_get_status, true)
_M.register("GET", "/metrics", handle_get_metrics, false)
_M.register("GET", "/summary", handle_get_summary, true)
_M.register("GET", "/csrf", handle_get_csrf, true)
_M.register("GET", "/upstreams/health", handle_get_upstream_health, true)
_M.register("GET", "/audit", handle_get_audit, true)

-- WAF rule management routes
-- Exact routes must be registered before parameterized ones so the
-- dispatch loop matches them first and returns immediately.
_M.register("GET",    "/waf/rules",              handle_list_waf_rules,     true)
_M.register("POST",   "/waf/rules",              handle_create_waf_rule,    true)
_M.register("GET",    "/waf/rules/history",      handle_waf_rule_history,   true)
_M.register("POST",   "/waf/rules/test",         handle_test_waf_rule,      true)
_M.register("POST",   "/waf/rules/reload",       handle_reload_waf_rules,   true)
_M.register("POST",   "/waf/rules/rollback",     handle_rollback_waf_rules, true)
_M.register("GET",    "/waf/stats",              handle_waf_stats,          true)
_M.register("GET",    "/waf/rules/:id",          handle_get_waf_rule,       true)
_M.register("PUT",    "/waf/rules/:id",          handle_update_waf_rule,    true)
_M.register("DELETE", "/waf/rules/:id",          handle_delete_waf_rule,    true)
_M.register("POST",   "/waf/rules/:id/enable",   handle_enable_waf_rule,   true)
_M.register("POST",   "/waf/rules/:id/disable",  handle_disable_waf_rule,  true)
_M.register("GET",    "/waf/stats/:id",          handle_waf_rule_stats,     true)
_M.register("GET",    "/waf/hits",               handle_list_waf_hits,      true)
_M.register("GET",    "/waf/hits/by-ip",          handle_waf_hits_by_ip,     true)
_M.register("GET",    "/waf/hits/:id",            handle_waf_hit_detail,     true)
_M.register("GET",    "/waf/timeline",            handle_waf_timeline,       true)
_M.register("GET",    "/waf/test-history",        handle_test_history,       true)
_M.register("DELETE", "/waf/test-history",        handle_clear_test_history, true)
_M.register("GET",    "/waf/analytics",           handle_waf_analytics,      true)
_M.register("POST",   "/waf/rules/:id/stage",    handle_stage_waf_rule,     true)
_M.register("POST",   "/waf/rules/:id/confirm",  handle_confirm_waf_rule,   true)
_M.register("DELETE", "/waf/rules/:id/pending",  handle_discard_waf_rule,   true)
_M.register("GET",    "/waf/rules/pending",      handle_list_pending_rules, true)

_M.register("GET",    "/config/export",          handle_export_config,       true)

-- GeoIP routes
_M.register("GET",    "/geoip/lookup",           handle_geoip_lookup,        true)
_M.register("GET",    "/geoip/stats",            handle_geoip_stats,         true)
_M.register("GET",    "/geoip/config",           handle_geoip_config,        true)
_M.register("PUT",    "/geoip/config",           handle_geoip_config_set,    true)
_M.register("GET",    "/geoip/status",           handle_geoip_status,        true)
_M.register("POST",   "/geoip/update",           handle_geoip_update,        true)

-- Fingerprint database routes
_M.register("GET",    "/fingerprints",           handle_fingerprint_list,    true)
_M.register("POST",   "/fingerprints",           handle_fingerprint_add,     true)
_M.register("PUT",    "/fingerprints",           handle_fingerprint_update,  true)
_M.register("DELETE", "/fingerprints/:id",       handle_fingerprint_delete,  true)
_M.register("GET",    "/fingerprints/stats",      handle_fingerprint_stats,   true)
_M.register("POST",   "/config/import",          handle_import_config,       true)

_M.register("GET",    "/plugins",                handle_list_plugins,        true)
_M.register("POST",   "/plugins/:id/toggle",     handle_toggle_plugin,       true)

_M.register("GET",    "/stats/top-paths",        handle_top_paths,           true)

_M.register("GET",    "/reputation/stats",        handle_reputation_stats,        true)
_M.register("GET",    "/reputation/flagged",      handle_reputation_flagged,      true)
_M.register("GET",    "/reputation/whitelist",    handle_reputation_whitelist,    true)
_M.register("GET",    "/reputation/score",        handle_reputation_score,        true)
_M.register("POST",   "/reputation/clear",        handle_reputation_clear,        true)
_M.register("POST",   "/reputation/whitelist",    handle_reputation_whitelist_add, true)
_M.register("DELETE", "/reputation/whitelist",    handle_reputation_whitelist_remove, true)
_M.register("POST",   "/reputation/persist",      handle_reputation_persist,      true)

-- Frequency limit routes
_M.register("GET",    "/frequency/stats",        handle_frequency_stats,     true)
_M.register("GET",    "/frequency/rules",        handle_frequency_rules,     true)
_M.register("POST",   "/frequency/rules",        handle_frequency_rule_save,true)
_M.register("DELETE", "/frequency/rules/:id",    handle_frequency_rule_delete,true)

-- ---------------------------------------------------------------------------
-- Router plugin hook: dispatched from plugin/router/init.lua
-- ---------------------------------------------------------------------------
function _M.dispatch(ctx)
    local uri = (ctx and ctx.request and ctx.request.uri) or ngx.var.uri
    local base_uri = (config and config.base_uri) or "/verynginx"
    local method = ngx.req.get_method()

    -- Only handle requests under base_uri
    if uri:find(base_uri, 1, true) ~= 1 then
        return
    end

    local path = uri:sub(#base_uri + 1)
    if path == "" then
        path = "/"
    end

    for _, route in ipairs(_M.routes) do
        -- Check exact match first, then parameterized match
        local matched = (route.path == path)
        local captures = {}
        if not matched and route.path:find(":id", 1, true) then
            -- Convert route path to Lua pattern: :id -> capture group
            local pattern = route.path:gsub(":id", "([^/]+)")
            local capture = path:match("^" .. pattern .. "$")
            if capture then
                matched = true
                captures[1] = capture
            end
        end
        if route.method == method and matched then
            if captures[1] then
                ngx.ctx.waf_rule_id = captures[1]
            end
            -- Auth check
            if route.auth_required then
                if not auth.middleware(ctx) then
                    ngx.status = 401
                    ctx.set_action(ctx, "response", {
                        code = 401,
                        response = {
                            code = 401,
                            content_type = "application/json; charset=utf-8",
                            body = json.encode({ ret = "failed", message = "unauthorized" })
                        }
                    })
                    return
                end
            end

            -- Rate limiting for authenticated routes (login has its own)
            if route.auth_required then
                local rl = require "api.rate_limit"
                local user = ctx and ctx.get_data and ctx.get_data(ctx, "auth:user") or "unknown"
                local rl_key = "api:" .. method .. ":" .. path .. ":" .. tostring(user)
                local limit, window = 60, 60
                if method == "POST" and path == "/config" then
                    limit, window = 30, 60
                end
                if not rl.allow(rl_key, limit, window) then
                    ngx.status = 429
                    ctx.set_action(ctx, "response", {
                        code = 429,
                        response = {
                            code = 429,
                            content_type = "application/json; charset=utf-8",
                            body = json.encode({ ret = "failed", message = "too many requests" })
                        }
                    })
                    return
                end
            end

            -- Rate limiting for unauthenticated routes (by IP)
            if not route.auth_required then
                local rl = require "api.rate_limit"
                local client_ip = ngx.var.remote_addr or "unknown"
                local rl_key = "api:" .. method .. ":" .. path .. ":" .. client_ip
                if not rl.allow(rl_key, 20, 60) then
                    ngx.status = 429
                    ctx.set_action(ctx, "response", {
                        code = 429,
                        response = {
                            code = 429,
                            content_type = "application/json; charset=utf-8",
                            body = json.encode({ ret = "failed", message = "too many requests" })
                        }
                    })
                    return
                end
            end

            -- Idempotency key check for mutating requests
            if method ~= "GET" and method ~= "HEAD" and method ~= "OPTIONS" then
                local idem_key = ngx.req.get_headers()["Idempotency-Key"]
                if idem_key and idem_key ~= "" then
                    local shared = ngx.shared.vn_locks
                    if shared then
                        local cache_key = "idempotent:" .. ngx.md5(idem_key)
                        if shared:get(cache_key) then
                            ngx.status = 409
                            ctx.set_action(ctx, "response", {
                                code = 409,
                                response = {
                                    code = 409,
                                    content_type = "application/json; charset=utf-8",
                                    body = json.encode({ ret = "failed", message = "conflict: duplicate request" })
                                }
                            })
                            return
                        end
                        shared:set(cache_key, true, 3600)
                    end
                end
            end

            -- Reset status so a previous route's 404 doesn't leak through
            ngx.status = 200

            -- Security headers
            ngx.header.content_type = "application/json; charset=utf-8"
            ngx.header["X-Content-Type-Options"] = "nosniff"
            ngx.header["X-Frame-Options"] = "SAMEORIGIN"
            ngx.header["X-XSS-Protection"] = "1; mode=block"
            ngx.header["Content-Security-Policy"] = table.concat({
                "default-src 'self';",
                "script-src 'self';",
                "style-src 'self' 'unsafe-inline';",
                "img-src 'self' data:;",
                "connect-src 'self';",
                "frame-ancestors 'self'",
            }, " ")

            local ok, response = pcall(route.handler)
            if not ok then
                ngx.log(ngx.ERR, "api dispatch error: ", tostring(response))
                ngx.status = 500
                response = json.encode({ ret = "failed", message = "internal error: " .. tostring(response) })
            end
            if not ngx.status or ngx.status == 0 then
                ngx.status = 200
            end

            -- Response size limit
            local max_response_size = 10485760
            if response and #response > max_response_size then
                ngx.status = 413
                response = json.encode({ ret = "failed", message = "response too large" })
            end

            -- Audit log for mutating operations
            if method ~= "GET" and method ~= "HEAD" and method ~= "OPTIONS" then
                local user = ctx and ctx.get_data and ctx.get_data(ctx, "auth:user") or "-"
                audit.log(method, path .. " status=" .. tostring(ngx.status), user)
            end

            ctx.set_action(ctx, "response", {
                code = ngx.status,
                response = {
                    code = ngx.status,
                    content_type = ngx.header.content_type or "application/json; charset=utf-8",
                    body = response or ""
                }
            })
            return
        end
    end
end

return _M