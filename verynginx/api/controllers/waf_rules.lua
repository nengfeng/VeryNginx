-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : WAF rule controller - CRUD, enable/disable, reload, history, rollback, staging flow

local _M = {}

local json = require "dkjson"
local audit = require "core.audit"
local helpers = require "api.helpers"
local waf_manager = require "waf-rule-manager"

local PENDING_PREFIX = "waf_pending_rule:"

-- ---------------------------------------------------------------------------
-- Pending-change index: a JSON id list in vn_config maintained under the same
-- spin-lock style used elsewhere (AGENTS §12.2). Replaces the old
-- get_keys(200) bounded scan, which silently truncated at 200 keys and was
-- O(N) over the whole dict. Live per-entry key ⇔ index entry (same invariant
-- as ip_rep pending index); dead entries pruned on read.
local PENDING_INDEX_KEY = "waf_pending_index"
local PENDING_INDEX_LOCK = "waf_pending:index_lock"

local function with_pending_lock(fn)
    local locks = ngx.shared.vn_locks
    if not locks then return fn() end -- no lock dict: best-effort (tests)
    local token = require("core.random").bytes(8)
    for _ = 1, 500 do
        if locks:add(PENDING_INDEX_LOCK, token, 5) then
            local ok, res = pcall(fn)
            if locks:get(PENDING_INDEX_LOCK) == token then locks:delete(PENDING_INDEX_LOCK) end
            if not ok then error(res) end
            return res
        end
        ngx.sleep(0.002)
    end
    ngx.log(ngx.ERR, "waf_rules: pending index lock timeout")
    return nil
end

local function pending_index_read(shared)
    local raw = shared:get(PENDING_INDEX_KEY)
    if not raw then return {} end
    local ok, arr = pcall(json.decode, raw)
    if ok and type(arr) == "table" then return arr end
    return {}
end

local function pending_index_write(shared, arr)
    shared:set(PENDING_INDEX_KEY, json.encode(arr), 0)
end

local function pending_index_add(rule_id)
    local shared = ngx.shared.vn_config
    if not shared then return end
    with_pending_lock(function()
        local arr = pending_index_read(shared)
        for _, e in ipairs(arr) do
            if e == rule_id then return end -- already indexed
        end
        arr[#arr + 1] = rule_id
        pending_index_write(shared, arr)
    end)
end

local function pending_index_remove(rule_id)
    local shared = ngx.shared.vn_config
    if not shared then return end
    with_pending_lock(function()
        local arr = pending_index_read(shared)
        local out, changed = {}, false
        for _, e in ipairs(arr) do
            if e == rule_id then changed = true else out[#out + 1] = e end
        end
        if changed then pending_index_write(shared, out) end
    end)
end


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
    if total_pages < 1 then total_pages = 1 end
    if page > total_pages then page = total_pages end
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

--- GET /waf/rules/:id - get a single rule
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

--- PUT /waf/rules/:id - update a rule
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

--- DELETE /waf/rules/:id - delete a rule
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

--- POST /waf/rules/:id/enable - enable a rule
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

--- POST /waf/rules/:id/disable - disable a rule
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

--- POST /waf/rules/:id/stage - save a rule change as pending (not yet active)
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

    local args = helpers.get_request_args()
    if not args or type(args) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid request body" })
    end

    -- Validate the proposed change against the live rule before staging, so
    -- invalid proposals are rejected at stage time (not only at confirm).
    local rules_obj = waf_manager.load_rules()
    local rules = (rules_obj and rules_obj.rules) or {}
    local found = false
    for _, rule in ipairs(rules) do
        if rule.id == rule_id then
            local candidate = {}
            for k, v in pairs(rule) do candidate[k] = v end
            for k, v in pairs(args) do
                if k ~= "id" then candidate[k] = v end
            end
            local vok, verr = waf_manager.validate_rule(candidate)
            if not vok then
                ngx.status = 400
                return json.encode({ ret = "failed", message = "invalid proposed change: " .. tostring(verr) })
            end
            found = true
            break
        end
    end
    if not found then
        ngx.status = 404
        return json.encode({ ret = "failed", message = "rule not found" })
    end

    local pending = {
        rule_id = rule_id,
        staged_at = ngx.time(),
        staged_by = "-",
        proposed = args,
    }
    shared:set(PENDING_PREFIX .. rule_id, json.encode(pending), 86400)
    pending_index_add(rule_id)
    audit.log("rule_staged", rule_id, "-")
    return json.encode({ ret = "success", data = pending })
end

--- POST /waf/rules/:id/confirm - activate a staged rule change
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
            -- Build a candidate (existing + proposed) and validate it before
            -- mutating the live rule; reject invalid proposals entirely.
            local candidate = {}
            for k, v in pairs(rule) do candidate[k] = v end
            for k, v in pairs(pending.proposed) do
                if k ~= "id" then candidate[k] = v end
            end
            local vok, verr = waf_manager.validate_rule(candidate)
            if not vok then
                ngx.status = 400
                return json.encode({ ret = "failed", message = "invalid proposed change: " .. tostring(verr) })
            end
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
        pending_index_remove(rule_id)
        ngx.status = 404
        return json.encode({ ret = "failed", message = "rule not found" })
    end

    -- Save the updated rules via config. On failure KEEP the pending slot so
    -- the operator can retry — deleting it here would silently destroy the
    -- staged change while the live rule set never received it.
    local sok, serr = waf_manager._save_rules_through_config(rules)
    if not sok then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "rule change persist failed: " .. tostring(serr) })
    end
    shared:delete(PENDING_PREFIX .. rule_id)
    pending_index_remove(rule_id)
    audit.log("rule_change_confirmed", rule_id, "-")
    return json.encode({ ret = "success", message = "rule change applied" })
end

--- DELETE /waf/rules/:id/pending - discard a staged rule change
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
    pending_index_remove(rule_id)
    if existed then
        audit.log("rule_change_discarded", rule_id, "-")
    end
    local msg = existed and "pending change discarded" or "no pending change"
    return json.encode({ ret = "success", message = msg })
end


--- GET /waf/rules/pending - list all pending rule changes
local function handle_list_pending_rules()
    local shared = ngx.shared.vn_config
    local result = {}
    if shared then
        -- Index-driven listing (dead entries pruned opportunistically under
        -- the lock). Legacy migration: an absent index falls back to the old
        -- bounded scan once and seeds the index from what it finds.
        local ids
        if shared:get(PENDING_INDEX_KEY) == nil then
            local seeded = {}
            for _, k in ipairs(shared:get_keys(200)) do
                if k:sub(1, #PENDING_PREFIX) == PENDING_PREFIX then
                    seeded[#seeded + 1] = k:sub(#PENDING_PREFIX + 1)
                end
            end
            with_pending_lock(function()
                if shared:get(PENDING_INDEX_KEY) == nil then
                    pending_index_write(shared, seeded)
                end
            end)
            ids = seeded
        else
            ids = with_pending_lock(function()
                local arr = pending_index_read(shared)
                local live, dead = {}, {}
                for _, id in ipairs(arr) do
                    if shared:get(PENDING_PREFIX .. id) ~= nil then
                        live[#live + 1] = id
                    else
                        dead[#dead + 1] = id
                    end
                end
                if #dead > 0 then pending_index_write(shared, live) end
                return live
            end) or {}
        end
        for _, id in ipairs(ids) do
            local data = shared:get(PENDING_PREFIX .. id)
            if data then
                local ok, decoded = pcall(json.decode, data)
                if ok and decoded then
                    result[#result + 1] = decoded
                end
            end
        end
    end
    return json.encode({ ret = "success", data = result })
end

function _M.register(api)
    api.register("GET",    "/waf/rules",              handle_list_waf_rules,     true)
    api.register("POST",   "/waf/rules",              handle_create_waf_rule,    true)
    api.register("GET",    "/waf/rules/history",      handle_waf_rule_history,   true)
    api.register("POST",   "/waf/rules/reload",       handle_reload_waf_rules,   true)
    api.register("POST",   "/waf/rules/rollback",     handle_rollback_waf_rules, true)
    api.register("GET",    "/waf/rules/:id",          handle_get_waf_rule,       true)
    api.register("PUT",    "/waf/rules/:id",          handle_update_waf_rule,    true)
    api.register("DELETE", "/waf/rules/:id",          handle_delete_waf_rule,    true)
    api.register("POST",   "/waf/rules/:id/enable",   handle_enable_waf_rule,    true)
    api.register("POST",   "/waf/rules/:id/disable",  handle_disable_waf_rule,   true)
    api.register("POST",   "/waf/rules/:id/stage",    handle_stage_waf_rule,     true)
    api.register("POST",   "/waf/rules/:id/confirm",  handle_confirm_waf_rule,   true)
    api.register("DELETE", "/waf/rules/:id/pending",  handle_discard_waf_rule,   true)
    api.register("GET",    "/waf/rules/pending",      handle_list_pending_rules, true)
end

return _M
