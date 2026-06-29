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
        ngx.log(ngx.NOTICE, "audit: login failed for user=", user, " reason=", result)
        return json.encode({ ret = "failed", message = result })
    end

    auth.set_session_cookie(result)
    ngx.status = 200
    ngx.log(ngx.NOTICE, "audit: login success user=", user)
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
                ngx.log(ngx.NOTICE, "audit: logout success")
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
    ngx.log(ngx.NOTICE, "audit: waf rule created id=", result.id, " name=", result.name)
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

--- POST /waf/rules/reload - force reload rules from file
local function handle_reload_waf_rules()
    local ok, err = waf_manager.reload()
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(err) })
    end
    ngx.log(ngx.NOTICE, "audit: waf rules reloaded")
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
    ngx.log(ngx.NOTICE, "audit: waf rules rolled back to version ", version)
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
    ngx.log(ngx.NOTICE, "audit: waf rule updated id=", rule_id, " version=", result.version)
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
    ngx.log(ngx.NOTICE, "audit: waf rule deleted id=", rule_id)
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
    ngx.log(ngx.NOTICE, "audit: waf rule enabled id=", rule_id)
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
    ngx.log(ngx.NOTICE, "audit: waf rule disabled id=", rule_id)
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
    local cfg = config_mod.data
    if not cfg.plugin then cfg.plugin = {} end
    if not cfg.plugin[name] then cfg.plugin[name] = {} end
    -- Determine current state
    local current = true
    if cfg.plugin[name].enable ~= nil then
        current = cfg.plugin[name].enable == true
    else
        local plugin_mod = require "core.plugin"
        for _, p in ipairs(plugin_mod.plugins) do
            if p.name == name then
                current = p.default_enable ~= false
                break
            end
        end
    end
    cfg.plugin[name].enable = not current
    local ok, err = config_mod.save(cfg)
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(err) })
    end
    return json.encode({ ret = "success", data = { name = name, enable = cfg.plugin[name].enable } })
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

_M.register("GET",    "/config/export",          handle_export_config,       true)
_M.register("POST",   "/config/import",          handle_import_config,       true)

_M.register("GET",    "/plugins",                handle_list_plugins,        true)
_M.register("POST",   "/plugins/:id/toggle",     handle_toggle_plugin,       true)

_M.register("GET",    "/stats/top-paths",        handle_top_paths,           true)

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

            local response = route.handler()
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
                ngx.log(ngx.NOTICE, "audit: user=", user, " method=", method, " path=", path, " status=", ngx.status)
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