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

local function is_scope_err(code)
    return code == "scope_validation_pending"
        or code == "scope_digest_mismatch"
        or code == "scope_unvalidated"
        or code == "helper_instance_changed"
        or code == "table_generation_changed"
end

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

local function collect_actual(exec, page_size)
    local actual_by_key = {}
    local actual_entries = {}
    local failed_groups = {}
    local list_fn = exec.list_strict or exec.list

    for _, list in ipairs(DROP_LISTS) do
        for _, family in ipairs(FAMILIES) do
            local group_key = list .. ":" .. family
            local cursor = 0
            repeat
                local list_ok, page, list_err = pcall(function()
                    return list_fn(list, family, cursor, page_size)
                end)
                if not list_ok or type(page) ~= "table" or list_err then
                    failed_groups[group_key] = true
                    break
                end
                for _, actual in ipairs(page.entries or {}) do
                    if actual.ip then
                        actual.set = actual.set or list
                        actual.family = actual.family or family
                        local key = list .. ":" .. family .. ":" .. tostring(actual.ip)
                        actual_by_key[key] = actual
                        actual_entries[#actual_entries + 1] = actual
                    end
                end
                cursor = page.next_cursor
            until not cursor
        end
    end

    return actual_by_key, actual_entries, failed_groups
end

-- ---------------------------------------------------------------------------
-- Pass 1: collect to_add and to_remove without mutating kernel.
-- Returns { to_add, to_update, to_remove } in desired-entry format.
-- ---------------------------------------------------------------------------
local function collect_drift(exec, all_desired, enforce, _now, page_size)
    local result = {
        to_add = {},
        to_update = {},
        to_remove = {},
        dry_run = not enforce,
        skipped_preserve = 0,
    }

    local desired_set = {}
    local actual_by_key, actual_entries, failed_groups = collect_actual(exec, page_size)

    for _, entry in ipairs(all_desired) do
        local key = entry.list .. ":" .. entry.family .. ":" .. entry.ip
        local group_key = entry.list .. ":" .. entry.family
        desired_set[key] = true
        local mode = entry.reconciliation_mode or "ensure"
        if failed_groups[group_key] then
            result.failed = (result.failed or 0) + 1
        elseif not actual_by_key[key] then
            if mode == "preserve_only" then
                result.skipped_preserve = result.skipped_preserve + 1
            else
                result.to_add[#result.to_add + 1] = entry
            end
        elseif mode == "preserve_only" then
            -- Present in both desired and kernel — refresh TTL via update
            result.to_update[#result.to_update + 1] = entry
        else
            result.to_update[#result.to_update + 1] = entry
        end
    end

    for _, actual in ipairs(actual_entries) do
        local list = actual.set or actual.list
        local family = actual.family or "ipv4"
        local key = list .. ":" .. family .. ":" .. tostring(actual.ip)
        if not desired_set[key] and not failed_groups[list .. ":" .. family] then
            result.to_remove[#result.to_remove + 1] = actual
        end
    end

    return result
end

-- ---------------------------------------------------------------------------
-- Pass 2 (enforce): apply chunked writes via executor.
-- ---------------------------------------------------------------------------
local function apply_chunked(exec, drift, _now, kb_cfg, result)
    local desired_gen = kb_cfg._desired_generation or 0
    local policy_gens = kb_cfg._policy_generations or {}

    local desired_entries = {}
    for _, e in ipairs(drift.to_add) do desired_entries[#desired_entries + 1] = e end
    for _, e in ipairs(drift.to_update) do desired_entries[#desired_entries + 1] = e end

    local chunks, snapshot_id = snapshot.split(
        desired_entries,
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
            if scope_err and is_scope_err(scope_err) then
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

    for _, entry in ipairs(drift.to_update) do
        local policy = list_to_policy(entry.list)
        if policy then
            local current = state_machine.get_policy(entry.ip, policy)
            if current and current.state ~= "installed" then
                state_machine.upsert(entry.ip, policy, "installed", entry.evidence or {}, {
                    list = entry.list,
                    family = entry.family,
                    installed_at = now,
                    expires_at = entry.expires_at or ((entry.ttl and entry.ttl > 0) and (now + entry.ttl) or nil),
                    source = entry.source or "automatic",
                    reason = "reconcile_update",
                })
            end
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

    -- Larger list pages mean fewer IPC round-trips when the kernel holds many
    -- entries (e.g. 100k+ entries would otherwise need 1000+ list calls).
    local list_page_size = kb_cfg.reconcile_list_page_size or 1000

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
    local drift = collect_drift(exec, all_desired, enforce, now, list_page_size)

    result.to_add = drift.to_add
    result.to_update = drift.to_update
    result.to_remove = drift.to_remove
    result.skipped_preserve = drift.skipped_preserve
    result.failed = drift.failed or 0

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
