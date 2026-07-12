-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking reconciliation (Phase 2: dry-run only).
--
-- Compares desired state (what should be installed) against actual state
-- (what the kernel/nftables currently has). In Phase 2 this is a dry-run:
-- it computes to_add/to_update/to_remove and logs "would_install" etc,
-- but does NOT send mutating IPC.

local _M = {}

local desired = require "core.kernel_blocking.desired_state"
local mock = require "core.kernel_blocking.executor_mock"
local config = require "core.config"

-- ---------------------------------------------------------------------------
-- Run one reconciliation round (dry-run for Phase 2).
-- Called from worker 0 periodic timer.
-- @param now number: ngx.time()
-- @return table: { to_add, to_update, to_remove, would_log }
-- ---------------------------------------------------------------------------
function _M.reconcile(_now)
    local kb_cfg = config.kernel_ip_blocking
    if not kb_cfg or kb_cfg.enabled ~= true then
        return { skipped = "disabled" }
    end

    local result = {
        to_add = {},
        to_update = {},
        to_remove = {},
        dry_run = true,
    }

    -- 1. Read desired state (paginated)
    local page_cursor = 0
    local all_desired = {}
    repeat
        local page = desired.list_desired(page_cursor, 500)
        for _, e in ipairs(page.entries) do
            all_desired[#all_desired + 1] = e
        end
        page_cursor = page.next_cursor
    until not page_cursor

    -- 2. For each desired entry, check actual state via mock executor
    for _, entry in ipairs(all_desired) do
        local ok, _ = mock.contains(entry.list, entry.family, entry.ip)
        if not ok then
            result.to_add[#result.to_add + 1] = entry
            ngx.log(ngx.INFO, "kernel_blocking DRY-RUN would_install: ",
                entry.list, "/", entry.ip)
        else
            -- Already installed (Phase 2 mock accepts all)
            result.to_update[#result.to_update + 1] = entry
        end
    end

    -- 3. Check for entries in actual state that are no longer desired
    -- (mock.list returns all; filter by desired list)
    -- Phase 2: simplified — actual state is read via mock.list
    local lists = { "scanner_drop", "cc_drop", "manual_drop" }
    local families = { "ipv4", "ipv6" }
    local desired_set = {}
    for _, e in ipairs(all_desired) do
        desired_set[e.list .. ":" .. e.family .. ":" .. e.ip] = true
    end
    for _, list in ipairs(lists) do
        for _, family in ipairs(families) do
            local cursor = 0
            repeat
                local page = mock.list(list, family, cursor)
                for _, actual in ipairs(page.entries) do
                    if not desired_set[list .. ":" .. family .. ":" .. actual.ip] then
                        result.to_remove[#result.to_remove + 1] = actual
                        ngx.log(ngx.INFO, "kernel_blocking DRY-RUN would_remove: ",
                            list, "/", actual.ip)
                    end
                end
                cursor = page.next_cursor
            until not cursor
        end
    end

    ngx.log(ngx.INFO, string.format(
        "kernel_blocking DRY-RUN reconcile: add=%d update=%d remove=%d",
        #result.to_add, #result.to_update, #result.to_remove))

    return result
end

return _M
