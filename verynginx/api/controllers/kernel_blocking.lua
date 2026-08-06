-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking controller (Design §11.5).
--             Exposes status, entries, candidates, and manual operations.

local _M = {}

local json = require "dkjson"

-- ---------------------------------------------------------------------------
-- GET /kernel-blocking/status
-- Returns comprehensive status including config, health, counters.
-- ---------------------------------------------------------------------------
local function handle_status()
    local config = require "core.config"
    local kb_cfg = config and config.kernel_ip_blocking
    if not kb_cfg then
        return json.encode({ ret = "failed", message = "kernel_ip_blocking not configured" })
    end

    local kb = require "core.kernel_blocking.init"
    local data = kb.status()
    return json.encode({ ret = "success", data = data })
end

-- ---------------------------------------------------------------------------
-- GET /kernel-blocking/entries?policy=scanner&cursor=0&page_size=50
-- Paginated list of installed entries from state machine + executor.
-- ---------------------------------------------------------------------------
local function handle_entries()
    local cursor = tonumber(ngx.var.arg_cursor) or 0
    local page_size = tonumber(ngx.var.arg_page_size) or 50
    page_size = math.min(page_size, 200)
    local policy_filter = ngx.var.arg_policy

    local sm = require "core.kernel_blocking.state_machine"
    local page = sm.list(cursor, page_size, "installed", policy_filter)

    -- Enrich from one executor listing per set/family instead of one full
    -- contains scan per row.
    local executor_mod = require "core.kernel_blocking.executor"
    local exec = executor_mod.get_executor()
    local groups = {}
    for _, e in ipairs(page.entries) do
        if e.list then
            local family = e.family or "ipv4"
            local group_key = e.list .. ":" .. family
            groups[group_key] = groups[group_key] or {
                list = e.list,
                family = family,
                entries = {},
            }
            groups[group_key].entries[#groups[group_key].entries + 1] = e
        else
            e.in_kernel = false
        end
    end

    for _, group in pairs(groups) do
        local present = {}
        local cursor2 = 0
        local list_ok = true
        repeat
            local ok, actual_page = pcall(function()
                return exec.list(group.list, group.family, cursor2)
            end)
            if not ok or type(actual_page) ~= "table" then
                list_ok = false
                break
            end
            for _, actual in ipairs(actual_page.entries or {}) do
                if actual.ip then present[actual.ip] = true end
            end
            cursor2 = actual_page.next_cursor
        until not cursor2
        for _, e in ipairs(group.entries) do
            e.in_kernel = list_ok and present[e.ip] == true
        end
    end

    return json.encode({
        ret = "success",
        data = {
            entries = page.entries,
            next_cursor = page.next_cursor,
        }
    })
end

-- ---------------------------------------------------------------------------
-- GET /kernel-blocking/candidates?state=candidate&cursor=0&page_size=50
-- Paginated list of candidates from state machine.
-- ---------------------------------------------------------------------------
local function handle_candidates()
    local cursor = tonumber(ngx.var.arg_cursor) or 0
    local page_size = tonumber(ngx.var.arg_page_size) or 50
    local state_filter = ngx.var.arg_state

    local sm = require "core.kernel_blocking.state_machine"
    local page = sm.list(cursor, page_size, state_filter)

    return json.encode({
        ret = "success",
        data = {
            entries = page.entries,
            next_cursor = page.next_cursor,
        }
    })
end

-- ---------------------------------------------------------------------------
-- POST /kernel-blocking/promote { ip, policy, ttl? }
-- Manually promote an IP to a drop set.
-- ---------------------------------------------------------------------------
local function handle_promote()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body or body == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "body required" })
    end
    local ok, req = pcall(json.decode, body)
    if not ok or type(req) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid JSON" })
    end
    local ip = req.ip
    local policy = req.policy or "scanner"
    local ttl = tonumber(req.ttl) or 86400
    if type(ttl) ~= "number" or ttl < 1 or ttl ~= ttl then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid ttl: must be a positive number of seconds" })
    end
    ttl = math.floor(ttl)
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip required" })
    end
    if type(ip) ~= "string"
        or not (ip:match("^[%d%.]+$") or ip:match("^[%da-fA-F:]+$")) then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid IP format" })
    end

    local config = require "core.config"
    local kb_cfg = config and config.kernel_ip_blocking
    local max_ttl = (kb_cfg and kb_cfg.scanner and kb_cfg.scanner.max_ttl) or 86400
    ttl = math.min(ttl, max_ttl)

    local set_name = ({scanner = "scanner_drop", cc = "cc_drop", manual = "manual_drop"})[policy]
    if not set_name then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid policy: " .. policy })
    end

    local family = (type(ip) == "string" and ip:find(":", 1, true)) and "ipv6" or "ipv4"

    -- Independent safety gates for manual promote (Design §16).
    local promotion = require "core.kernel_blocking.promotion"
    if promotion.is_reserved_address then
        local reserved, why = promotion.is_reserved_address(ip, family)
        if reserved then
            ngx.status = 400
            return json.encode({ ret = "failed", message = "reserved_address", reason = why })
        end
    end
    do
        local ir = require "core.ip_reputation"
        if ir.is_whitelisted and ir.is_whitelisted(ip) then
            ngx.status = 403
            return json.encode({ ret = "failed", message = "whitelisted" })
        end
    end
    if promotion.capacity_available then
        local cap_ok = promotion.capacity_available(set_name)
        if not cap_ok then
            ngx.status = 429
            return json.encode({ ret = "failed", message = "capacity_exceeded" })
        end
    end

    local executor_mod = require "core.kernel_blocking.executor"
    local exec = executor_mod.get_executor()
    local sm = require "core.kernel_blocking.state_machine"

    local call_ok, add_ok, add_err = pcall(function()
        return exec.add(set_name, family, ip, ttl)
    end)

    if not call_ok or not add_ok then
        ngx.status = 500
        return json.encode({
            ret = "failed",
            message = tostring(add_err or add_ok or "add_failed"),
        })
    end

    local desired = require "core.kernel_blocking.desired_state"
    desired.set_desired(ip, family, set_name, { reason = "manual_promote" }, ttl, {
        source = "manual",
        policy = policy,
        reason = "manual_promote",
        reconciliation_mode = "manual",
    })

    sm.upsert(ip, policy, "installed", {
        reason = "manual_promote",
    }, {
        list = set_name,
        family = family,
        installed_at = ngx.time(),
        expires_at = ngx.time() + ttl,
        source = "manual",
        reconciliation_mode = "manual",
    })

    pcall(function()
        local audit = require "core.audit"
        audit.log("kernel_blocking.promote", policy .. " " .. ip .. " ttl=" .. tostring(ttl))
    end)
    pcall(function()
        local metrics = require "core.metrics"
        metrics.incr("verynginx_kernel_block_promotions_total", 1, {
            list = set_name, result = "manual",
        })
    end)

    return json.encode({
        ret = "success",
        data = { ip = ip, set = set_name, ttl = ttl, family = family }
    })
end

-- ---------------------------------------------------------------------------
-- POST /kernel-blocking/clear { ip }
-- Manually clear an IP from all drop sets.
-- ---------------------------------------------------------------------------
local function handle_clear()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body or body == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "body required" })
    end
    local ok, req = pcall(json.decode, body)
    if not ok or type(req) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid JSON" })
    end
    local ip = req.ip
    if not ip or ip == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "ip required" })
    end

    local executor_mod = require "core.kernel_blocking.executor"
    local exec = executor_mod.get_executor()
    local sm = require "core.kernel_blocking.state_machine"
    local desired = require "core.kernel_blocking.desired_state"

    -- Try deleting from all 3 drop sets for both families
    local sets = { "scanner_drop", "cc_drop", "manual_drop" }
    local families = { "ipv4", "ipv6" }
    local removed = 0
    for _, set_name in ipairs(sets) do
        for _, family in ipairs(families) do
            local chk_ok, exists = pcall(function()
                return exec.contains(set_name, family, ip)
            end)
            if chk_ok and exists then
                local rm_ok, rm_result = pcall(function()
                    return exec.delete(set_name, family, ip)
                end)
                if rm_ok and rm_result ~= false then removed = removed + 1 end
            end
        end
    end

    desired.clear_for_ip(ip)

    -- Clear from all policies (scanner, cc, manual)
    for _, policy in ipairs({ "scanner", "cc", "manual" }) do
        sm.transition(ip, policy, "cleared", { cleared_at = ngx.time(), reason = "manual_clear" })
    end

    pcall(function()
        local audit = require "core.audit"
        audit.log("kernel_blocking.clear", ip)
    end)
    pcall(function()
        local metrics = require "core.metrics"
        metrics.incr("verynginx_kernel_block_operations_total", 1, {
            operation = "clear", result = "ok",
        })
    end)

    return json.encode({
        ret = "success",
        data = { ip = ip, removed = removed }
    })
end

-- ---------------------------------------------------------------------------
-- POST /kernel-blocking/pause { paused: true|false }
-- Toggle emergency pause without clearing state.
-- ---------------------------------------------------------------------------
local function handle_pause()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body or body == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "body required" })
    end
    local ok, req = pcall(json.decode, body)
    if not ok or type(req) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid JSON" })
    end
    if type(req.paused) ~= "boolean" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "paused boolean required" })
    end

    -- Load full config (via report), mutate emergency_pause, save
    -- NOTE: report() encodes config_data which may contain function refs
    -- (module-level helpers). Use pcall to catch JSON errors and fall back
    -- to a direct config_data accessor pattern.
    local config_mod = require "core.config"
    local cfg = nil
    local report_ok, report_val = pcall(function() return config_mod.report() end)
    if report_ok and report_val then
        cfg = json.decode(report_val)
    end
    -- Fallback: load from file directly
    if not cfg then
        config_mod.load_from_file()
        local report_ok2, report_val2 = pcall(function() return config_mod.report() end)
        if report_ok2 and report_val2 then
            cfg = json.decode(report_val2)
        end
    end
    if not cfg then
        ngx.status = 500
        return json.encode({ ret = "failed", message = "config load failed" })
    end
    cfg.kernel_ip_blocking = cfg.kernel_ip_blocking or {}
    cfg.kernel_ip_blocking.emergency_pause = req.paused

    local save_ok, save_err = config_mod.save(cfg)
    if not save_ok then
        ngx.status = 500
        return json.encode({ ret = "failed", message = tostring(save_err) })
    end

    return json.encode({
        ret = "success",
        data = { paused = req.paused }
    })
end

-- ---------------------------------------------------------------------------
-- POST /kernel-blocking/flush-auto
-- Flush all auto-owned entries (scanner_drop + cc_drop).
-- ---------------------------------------------------------------------------
local function handle_flush_auto()
    local executor_mod = require "core.kernel_blocking.executor"
    local exec = executor_mod.get_executor()
    local desired = require "core.kernel_blocking.desired_state"
    local sm = require "core.kernel_blocking.state_machine"

    local ok, flush_result = pcall(function()
        return exec.flush_owned("auto")
    end)

    if not ok then
        ngx.status = 500
        return json.encode({ ret = "failed", message = tostring(flush_result) })
    end

    desired.clear_auto()
    for _, policy in ipairs({ "scanner", "cc" }) do
        local page = sm.list(0, 500, "installed", policy)
        for _, e in ipairs(page.entries or {}) do
            sm.transition(e.ip, policy, "cleared", {
                cleared_at = ngx.time(),
                reason = "flush_auto",
            })
        end
    end

    return json.encode({
        ret = "success",
        data = { removed = (flush_result and flush_result.removed) or 0 }
    })
end

-- ---------------------------------------------------------------------------
-- POST /kernel-blocking/reconcile
-- Manually trigger a reconciliation round.
-- ---------------------------------------------------------------------------
local function handle_reconcile()
    local kb = require "core.kernel_blocking.init"
    local result = kb.reconcile(ngx.time())
    pcall(function()
        local audit = require "core.audit"
        audit.log("kernel_blocking.reconcile", "manual")
    end)
    return json.encode({ ret = "success", data = result })
end

-- ---------------------------------------------------------------------------
-- GET /kernel-blocking/bucket-history
-- Returns sampled token balance history for trend chart (Design §12.2).
-- ---------------------------------------------------------------------------
local function handle_bucket_history()
    local kb = require "core.kernel_blocking.init"
    local history = kb.get_bucket_history()
    return json.encode({ ret = "success", data = { samples = history } })
end

-- ---------------------------------------------------------------------------
-- GET /kernel-blocking/diff
-- Returns desired-vs-actual drift for diff visualization (Design §12.2).
-- ---------------------------------------------------------------------------
local function handle_diff()
    local kb = require "core.kernel_blocking.init"
    local diff = kb.get_diff()
    return json.encode({ ret = "success", data = diff })
end

-- ---------------------------------------------------------------------------
-- Route registration
-- ---------------------------------------------------------------------------
function _M.register(api)
    api.register("GET", "/kernel-blocking/status", handle_status)
    api.register("GET", "/kernel-blocking/entries", handle_entries)
    api.register("GET", "/kernel-blocking/candidates", handle_candidates)
    api.register("POST", "/kernel-blocking/promote", handle_promote)
    api.register("POST", "/kernel-blocking/clear", handle_clear)
    api.register("POST", "/kernel-blocking/pause", handle_pause)
    api.register("POST", "/kernel-blocking/flush-auto", handle_flush_auto)
    api.register("POST", "/kernel-blocking/reconcile", handle_reconcile)
    api.register("GET", "/kernel-blocking/bucket-history", handle_bucket_history)
    api.register("GET", "/kernel-blocking/diff", handle_diff)
end

return _M
