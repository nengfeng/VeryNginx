-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking reconciliation.
--             Compares desired state vs actual executor state.
--             observe mode: dry-run only (log would_*).
--             enforce mode: apply add/delete to repair drift.

local _M = {}

local desired = require "core.kernel_blocking.desired_state"
local executor_mod = require "core.kernel_blocking.executor"
local state_machine = require "core.kernel_blocking.state_machine"
local config = require "core.config"

local DROP_LISTS = { "scanner_drop", "cc_drop", "manual_drop" }
local FAMILIES = { "ipv4", "ipv6" }

local function list_to_policy(list)
    if list == "scanner_drop" then return "scanner" end
    if list == "cc_drop" then return "cc" end
    if list == "manual_drop" then return "manual" end
    return nil
end

local function remaining_ttl(entry, now)
    if entry.ttl and entry.ttl > 0 and not entry.expires_at then
        return entry.ttl
    end
    if entry.expires_at then
        return math.max(entry.expires_at - now, 1)
    end
    return 0
end

-- ---------------------------------------------------------------------------
-- Health-check-driven scope_validation_pending transitions.
-- ---------------------------------------------------------------------------
local function health_check_transitions(exec)
    local ok, health = pcall(function() return exec.health() end)
    local helper_up = ok and health and health.state == "ok"

    if not helper_up then
        local page = state_machine.list(0, 500, "installed")
        for _, e in ipairs(page.entries) do
            state_machine.to_scope_validation_pending(e.ip, e.policy)
        end
        return "unreachable"
    end

    local pending = state_machine.list(0, 500, "scope_validation_pending")
    for _, e in ipairs(pending.entries) do
        local exists = false
        if e.list then
            local call_ok, present = pcall(function()
                return exec.contains(e.list, e.family or "ipv4", e.ip)
            end)
            exists = call_ok and present and true or false
        end
        state_machine.from_scope_validation_pending(e.ip, e.policy, exists)
    end
    return "ok"
end

-- Heal: installed SM entries without desired get backfilled so enforce
-- reconcile does not mass-delete pre-wiring installs.
local function backfill_desired_from_state_machine(now)
    local cursor = 0
    repeat
        local page = state_machine.list(cursor, 500, "installed")
        for _, e in ipairs(page.entries) do
            if e.list and e.ip then
                local family = e.family or "ipv4"
                if not desired.get_desired(e.ip, family, e.list) then
                    local ttl = remaining_ttl(e, now)
                    if ttl <= 0 then ttl = 3600 end
                    desired.set_desired(e.ip, family, e.list, e.evidence or {}, ttl, {
                        source = e.source or "automatic",
                        policy = e.policy,
                        reason = "backfill_from_state_machine",
                    })
                end
            end
        end
        cursor = page.next_cursor
    until not cursor
end

local function collect_all_desired(now)
    local all = {}
    local expired = {}
    local page_cursor = 0
    repeat
        local page = desired.list_desired(page_cursor, 500)
        for _, e in ipairs(page.entries) do
            if e.expires_at and e.expires_at <= now then
                expired[#expired + 1] = e
            else
                all[#all + 1] = e
            end
        end
        page_cursor = page.next_cursor
    until not page_cursor

    -- Mutate after full scan so pagination cursors stay stable.
    for _, e in ipairs(expired) do
        desired.remove_desired(e.ip, e.family, e.list)
        local policy = list_to_policy(e.list)
        if policy then
            state_machine.transition(e.ip, policy, "expired", {
                reason = "desired_ttl_elapsed",
                expired_at = now,
            })
        end
    end
    return all
end

local function safe_contains(exec, list, family, ip)
    local call_ok, present = pcall(function()
        return exec.contains(list, family, ip)
    end)
    if not call_ok then
        return false, "contains_error"
    end
    return present and true or false, nil
end

local function apply_add(exec, entry, now, result)
    local ttl = remaining_ttl(entry, now)
    local call_ok, add_ok, add_err = pcall(function()
        return exec.add(entry.list, entry.family, entry.ip, ttl)
    end)
    if not call_ok or not add_ok then
        result.failed = result.failed + 1
        local policy = list_to_policy(entry.list)
        if policy then
            state_machine.upsert(entry.ip, policy, "degraded", entry.evidence or {}, {
                list = entry.list,
                family = entry.family,
                reason = "reconcile_add_failed",
                error = tostring(add_err or add_ok),
            })
        end
        ngx.log(ngx.ERR, "kernel_blocking reconcile add failed: ",
            entry.list, "/", entry.ip, " err=", tostring(add_err or add_ok))
        return false
    end

    result.applied_add = result.applied_add + 1
    local policy = list_to_policy(entry.list)
    if policy then
        state_machine.upsert(entry.ip, policy, "installed", entry.evidence or {}, {
            list = entry.list,
            family = entry.family,
            installed_at = now,
            expires_at = entry.expires_at or (ttl > 0 and (now + ttl) or nil),
            source = entry.source or "automatic",
            reason = "reconcile_add",
        })
    end
    return true
end

local function apply_remove(exec, actual, result)
    local list = actual.set or actual.list
    local family = actual.family or "ipv4"
    local ip = actual.ip
    if not list or not ip then
        result.failed = result.failed + 1
        return false
    end

    local call_ok, del_ok, del_err = pcall(function()
        return exec.delete(list, family, ip)
    end)
    if not call_ok or del_ok == false then
        result.failed = result.failed + 1
        ngx.log(ngx.ERR, "kernel_blocking reconcile delete failed: ",
            list, "/", ip, " err=", tostring(del_err or del_ok))
        return false
    end

    result.applied_remove = result.applied_remove + 1
    desired.remove_desired(ip, family, list)
    local policy = list_to_policy(list)
    if policy then
        local current = state_machine.get_policy(ip, policy)
        if current and current.state == "expired" then
            -- Keep expired; kernel cleanup only.
            state_machine.transition(ip, policy, "expired", {
                reason = "desired_ttl_elapsed_kernel_removed",
                cleared_at = ngx.time(),
            })
        else
            state_machine.transition(ip, policy, "cleared", {
                reason = "reconcile_remove_orphan",
                cleared_at = ngx.time(),
            })
        end
    end
    return true
end

-- ---------------------------------------------------------------------------
-- Run one reconciliation round.
-- @param now number: ngx.time()
-- @return table
-- ---------------------------------------------------------------------------
function _M.reconcile(now)
    now = now or ngx.time()
    local kb_cfg = config.kernel_ip_blocking
    if not kb_cfg or kb_cfg.enabled ~= true then
        return { skipped = "disabled" }
    end

    local exec = executor_mod.get_executor()
    local health_status = health_check_transitions(exec)
    local enforce = (kb_cfg.mode == "enforce")

    -- Do not mutate kernel while helper is down (fail-open).
    if enforce and health_status ~= "ok" then
        return {
            skipped = "helper_unreachable",
            health = health_status,
            dry_run = false,
            to_add = {},
            to_update = {},
            to_remove = {},
            applied_add = 0,
            applied_remove = 0,
            failed = 0,
        }
    end

    if enforce then
        backfill_desired_from_state_machine(now)
    end

    local result = {
        to_add = {},
        to_update = {},
        to_remove = {},
        dry_run = not enforce,
        health = health_status,
        applied_add = 0,
        applied_remove = 0,
        failed = 0,
    }

    local all_desired = collect_all_desired(now)
    local desired_set = {}

    for _, entry in ipairs(all_desired) do
        desired_set[entry.list .. ":" .. entry.family .. ":" .. entry.ip] = true
        local present, cerr = safe_contains(exec, entry.list, entry.family, entry.ip)
        if cerr then
            result.failed = result.failed + 1
        elseif not present then
            result.to_add[#result.to_add + 1] = entry
            if enforce then
                apply_add(exec, entry, now, result)
            else
                ngx.log(ngx.INFO, "kernel_blocking DRY-RUN would_install: ",
                    entry.list, "/", entry.ip)
            end
        else
            result.to_update[#result.to_update + 1] = entry
        end
    end

    for _, list in ipairs(DROP_LISTS) do
        for _, family in ipairs(FAMILIES) do
            local cursor = 0
            repeat
                local page = { entries = {}, next_cursor = nil }
                local list_ok, list_page = pcall(function()
                    return exec.list(list, family, cursor)
                end)
                if list_ok and type(list_page) == "table" then
                    page = list_page
                end
                for _, actual in ipairs(page.entries or {}) do
                    local ip = actual.ip
                    if ip and not desired_set[list .. ":" .. family .. ":" .. ip] then
                        actual.set = actual.set or list
                        actual.family = actual.family or family
                        result.to_remove[#result.to_remove + 1] = actual
                        if enforce then
                            apply_remove(exec, actual, result)
                        else
                            ngx.log(ngx.INFO, "kernel_blocking DRY-RUN would_remove: ",
                                list, "/", ip)
                        end
                    end
                end
                cursor = page.next_cursor
            until not cursor
        end
    end

    if enforce then
        ngx.log(ngx.INFO, string.format(
            "kernel_blocking reconcile apply: add=%d remove=%d failed=%d (planned add=%d update=%d remove=%d)",
            result.applied_add, result.applied_remove, result.failed,
            #result.to_add, #result.to_update, #result.to_remove))
    else
        ngx.log(ngx.INFO, string.format(
            "kernel_blocking DRY-RUN reconcile: add=%d update=%d remove=%d",
            #result.to_add, #result.to_update, #result.to_remove))
    end

    return result
end

return _M
