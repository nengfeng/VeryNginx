-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking reconciliation.
--             Compares desired state vs actual executor state.
--             observe mode: dry-run only (log would_*).
--             enforce mode: apply add/delete to repair drift.
--
--             Design §8.3.3: desired state exceeding chunk_size is split
--             into chunks with snapshot_id/chunk_index/final_chunk.
--             Remove operations are deferred to the final chunk so the
--             Helper never deletes entries based on a partial snapshot.

local _M = {}

local desired = require "core.kernel_blocking.desired_state"
local executor_mod = require "core.kernel_blocking.executor"
local state_machine = require "core.kernel_blocking.state_machine"
local config = require "core.config"
local snapshot = require "core.kernel_blocking.snapshot"

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

    -- Protected Scope Binding (Design §8.3.4 / §10.4).
    do
        local ok_sb, sb = pcall(require, "core.kernel_blocking.scope_binding")
        if ok_sb and sb then
            local vok, vreason = sb.validate_health(health)
            if not vok then
                -- Try re-bootstrap before pausing DROP reconcile.
                local rebound = false
                if exec.rebind_scope then
                    local call_ok, ok_rb = pcall(function()
                        return exec.rebind_scope()
                    end)
                    if call_ok and ok_rb and sb.drop_writes_allowed() then
                        rebound = true
                    end
                elseif exec.ensure_base then
                    local call_ok, ok_eb = pcall(function()
                        return exec.ensure_base(config.kernel_ip_blocking)
                    end)
                    if call_ok and ok_eb and sb.drop_writes_allowed() then
                        rebound = true
                    end
                end
                if not rebound then
                    local page = state_machine.list(0, 500, "installed")
                    for _, e in ipairs(page.entries) do
                        state_machine.to_scope_validation_pending(e.ip, e.policy)
                    end
                    return vreason or "scope_validation_pending"
                end
            end
        end
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

-- ---------------------------------------------------------------------------
-- Pass 1: collect to_add and to_remove without mutating kernel.
-- Returns { to_add, to_update, to_remove } in desired-entry format.
-- ---------------------------------------------------------------------------
local function collect_drift(exec, all_desired, enforce, now)
    local result = {
        to_add = {},
        to_update = {},
        to_remove = {},
        dry_run = not enforce,
        skipped_preserve = 0,
    }

    local desired_set = {}
    local preserve_set = {}

    for _, entry in ipairs(all_desired) do
        local key = entry.list .. ":" .. entry.family .. ":" .. entry.ip
        desired_set[key] = true
        local mode = entry.reconciliation_mode or "ensure"
        if mode == "preserve_only" then
            preserve_set[key] = true
        end
        local present, cerr = safe_contains(exec, entry.list, entry.family, entry.ip)
        if cerr then
            result.failed = (result.failed or 0) + 1
        elseif not present then
            if mode == "preserve_only" then
                result.skipped_preserve = result.skipped_preserve + 1
            else
                result.to_add[#result.to_add + 1] = entry
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
                    local key = list .. ":" .. family .. ":" .. tostring(ip)
                    if ip and not desired_set[key] then
                        actual.set = actual.set or list
                        actual.family = actual.family or family
                        result.to_remove[#result.to_remove + 1] = actual
                    elseif ip and preserve_set[key] then
                        -- present preserve_only entry: keep until natural TTL
                        result.to_update[#result.to_update + 1] = actual
                    end
                end
                cursor = page.next_cursor
            until not cursor
        end
    end

    return result
end

-- ---------------------------------------------------------------------------
-- Pass 2 (enforce): apply chunked writes via executor.
-- ---------------------------------------------------------------------------
local function apply_chunked(exec, drift, now, kb_cfg, result)
    local desired_gen = kb_cfg._desired_generation or 0
    local policy_gens = kb_cfg._policy_generations or {}

    local chunks, snapshot_id = snapshot.split(
        drift.to_add,
        drift.to_remove,
        {
            chunk_size = kb_cfg.reconcile_chunk_size or 500,
            desired_generation = desired_gen,
            policy_generations = policy_gens,
        }
    )

    result.snapshot_id = snapshot_id
    result.total_chunks = #chunks
    result.chunks_sent = 0
    result.chunks_ok = 0

    local scope_invalidated = false

    local function invalidate_scope(reason)
        if scope_invalidated then return end
        local ok_sb, sb = pcall(require, "core.kernel_blocking.scope_binding")
        if ok_sb and sb then
            sb.invalidate(reason)
            scope_invalidated = true
        end
    end

    for _, chunk in ipairs(chunks) do
        result.chunks_sent = result.chunks_sent + 1

        local chunk_result, scope_err = exec.chunked_reconcile(chunk)
        if not chunk_result then
            result.failed = result.failed + #chunk.desired + #chunk.remove
            result.last_error = scope_err or "chunk_reconcile_failed"
            if scope_err then
                invalidate_scope(scope_err)
            end
            return false
        end

        if scope_err then
            -- scope issue reported but chunk_result present
            result.last_error = scope_err
            invalidate_scope(scope_err)
            return false
        end

        result.chunks_ok = result.chunks_ok + 1
        result.applied_add = result.applied_add + (chunk_result.added or 0)
        result.applied_remove = result.applied_remove + (chunk_result.removed or 0)
        result.updated_count = (result.updated_count or 0) + (chunk_result.updated or 0)
        result.preserved_count = (result.preserved_count or 0) + (chunk_result.preserved or 0)
    end

    return true
end

-- ---------------------------------------------------------------------------
-- After successful chunked reconcile, update state machine for entries
-- that were included in the snapshot.
-- ---------------------------------------------------------------------------
local function update_state_machine_after_apply(drift, now)
    for _, entry in ipairs(drift.to_add) do
        local policy = list_to_policy(entry.list)
        if policy then
            state_machine.upsert(entry.ip, policy, "installed", entry.evidence or {}, {
                list = entry.list,
                family = entry.family,
                installed_at = now,
                expires_at = entry.expires_at or ((entry.ttl and entry.ttl > 0) and (now + entry.ttl) or nil),
                source = entry.source or "automatic",
                reason = "reconcile_add",
            })
        end
    end

    for _, actual in ipairs(drift.to_remove) do
        local list = actual.set or actual.list
        local family = actual.family or "ipv4"
        local policy = list_to_policy(list)
        if policy then
            local current = state_machine.get_policy(actual.ip, policy)
            if current and current.state == "expired" then
                state_machine.transition(actual.ip, policy, "expired", {
                    reason = "desired_ttl_elapsed_kernel_removed",
                    cleared_at = now,
                })
            else
                state_machine.transition(actual.ip, policy, "cleared", {
                    reason = "reconcile_remove_orphan",
                    cleared_at = now,
                })
            end
            desired.remove_desired(actual.ip, family, list)
        end
    end
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
        local skip = "helper_unreachable"
        if health_status and health_status ~= "unreachable" then
            skip = health_status
        end
        return {
            skipped = skip,
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
        skipped_preserve = 0,
        snapshot_id = nil,
        total_chunks = 0,
        chunks_sent = 0,
        chunks_ok = 0,
    }

    -- Pass 1: collect drift (read-only).
    local all_desired = collect_all_desired(now)
    local drift = collect_drift(exec, all_desired, enforce, now)

    result.to_add = drift.to_add
    result.to_update = drift.to_update
    result.to_remove = drift.to_remove
    result.skipped_preserve = drift.skipped_preserve

    -- Compute snapshot metadata (chunk count) for observability even in dry-run.
    local total_chunks = snapshot.chunk_count(drift.to_add, drift.to_remove,
        kb_cfg.reconcile_chunk_size or 500)
    result.total_chunks = total_chunks
    if total_chunks > 1 then
        result.snapshot_id = snapshot.new_id()
    end

    if enforce then
        -- Pass 2: apply via chunked writes.
        local ok = apply_chunked(exec, drift, now, kb_cfg, result)
        if ok then
            update_state_machine_after_apply(drift, now)
        end

        ngx.log(ngx.INFO, string.format(
            "kernel_blocking reconcile apply: chunks=%d/%d add=%d remove=%d failed=%d snapshot=%s",
            result.chunks_ok, result.total_chunks,
            result.applied_add, result.applied_remove, result.failed,
            result.snapshot_id or "none"))
    else
        -- observe mode: dry-run logging.
        for _, e in ipairs(drift.to_add) do
            ngx.log(ngx.INFO, "kernel_blocking DRY-RUN would_install: ",
                e.list, "/", e.ip)
        end
        for _, r in ipairs(drift.to_remove) do
            ngx.log(ngx.INFO, "kernel_blocking DRY-RUN would_remove: ",
                (r.set or r.list), "/", r.ip)
        end
        ngx.log(ngx.INFO, string.format(
            "kernel_blocking DRY-RUN reconcile: add=%d update=%d remove=%d",
            #drift.to_add, #drift.to_update, #drift.to_remove))
    end

    return result
end

return _M
