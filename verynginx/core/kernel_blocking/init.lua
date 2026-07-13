-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking lifecycle facade: restore/persist/bootstrap,
--             process_candidates/reconcile wrappers, metrics gauges.
--             Design §10.3 / §10.5 / §11.5.

local _M = {}

local json = require "dkjson"
local config = require "core.config"
local desired = require "core.kernel_blocking.desired_state"
local sm = require "core.kernel_blocking.state_machine"
local lifecycle = require "core.kernel_blocking.lifecycle"
local readiness = require "core.kernel_blocking.readiness"

local STATE_VERSION = 1
local LEASE_DICT = "vn_locks"
-- Design §10.3: tokenized TTL leases prevent slow-call overlap and dual
-- worker-generation execution after graceful reload.
local PERSIST_LEASE = "kb:lease:persist"
local RECONCILE_LEASE = "kb:lease:reconcile"
local DISPATCH_LEASE = "kb:lease:dispatch"
local BATCH_LEASE = "kb:lease:batch"

local DEFAULT_LEASE_TTL = {
    batch = 30,
    reconcile = 60,
    dispatch = 30,
    persist = 30,
}

local function worker_id()
    if ngx.worker and ngx.worker.id then
        return ngx.worker.id() or 0
    end
    return 0
end

local function state_path()
    local root = config.resolve_path()
    if not root:match("/$") then root = root .. "/" end
    return root .. "configs/kernel-blocking-state.json"
end

local function acquire_lease(name, ttl)
    local s = ngx.shared[LEASE_DICT]
    if not s then return true, "no_shared" end
    ttl = ttl or 30
    local token = tostring(ngx.time()) .. ":" .. tostring(worker_id()) .. ":"
        .. tostring(math.random(1, 1e9))
    local meta = json.encode({
        token = token,
        worker_id = worker_id(),
        acquired_at = ngx.time(),
        ttl = ttl,
        name = name,
    })
    local ok = s:add(name, meta, ttl)
    if ok then return true, token end
    return false, "busy"
end

local function release_lease(name, token)
    local s = ngx.shared[LEASE_DICT]
    if not s or not token or token == "no_shared" then return end
    local raw = s:get(name)
    if not raw then return end
    if raw == token then
        s:delete(name)
        return
    end
    local ok, meta = pcall(json.decode, raw)
    if ok and type(meta) == "table" and meta.token == token then
        s:delete(name)
    end
end

local function peek_lease(name)
    local s = ngx.shared[LEASE_DICT]
    if not s then
        return { held = false, reason = "no_shared" }
    end
    local raw = s:get(name)
    if not raw then
        return { held = false }
    end
    local ok, meta = pcall(json.decode, raw)
    if ok and type(meta) == "table" then
        return {
            held = true,
            worker_id = meta.worker_id,
            acquired_at = meta.acquired_at,
            ttl = meta.ttl,
            age = meta.acquired_at and (ngx.time() - meta.acquired_at) or nil,
        }
    end
    return { held = true, opaque = true }
end

function _M.lease_status()
    return {
        batch = peek_lease(BATCH_LEASE),
        reconcile = peek_lease(RECONCILE_LEASE),
        dispatch = peek_lease(DISPATCH_LEASE),
        persist = peek_lease(PERSIST_LEASE),
    }
end

function _M.restore()
    if worker_id() ~= 0 then return end
    lifecycle.ensure_initialized()
    local path = state_path()
    local f = io.open(path, "r")
    if not f then
        ngx.log(ngx.INFO, "kernel_blocking: no persist file at ", path)
        return
    end
    local data = f:read("*all")
    f:close()
    if not data or data == "" then return end
    local ok, payload = pcall(json.decode, data)
    if not ok or type(payload) ~= "table" then
        ngx.log(ngx.ERR, "kernel_blocking: persist decode failed")
        return
    end
    if payload.version and payload.version ~= STATE_VERSION then
        ngx.log(ngx.WARN, "kernel_blocking: unsupported state version ",
            tostring(payload.version))
        return
    end

    if type(payload.lifecycle) == "table" then
        lifecycle.import_state(payload.lifecycle)
    end

    local now = ngx.time()
    local restored = 0
    for _, e in ipairs(payload.entries or {}) do
        if type(e) == "table" and e.ip and e.list and e.family then
            if e.expires_at and e.expires_at <= now and e.source ~= "manual" then
                goto continue
            end
            local ttl = 0
            if e.expires_at and e.expires_at > now then
                ttl = e.expires_at - now
            end
            local mode = e.reconciliation_mode or (e.source == "manual" and "manual" or "ensure")
            desired.set_desired(e.ip, e.family, e.list, e.evidence or {}, ttl, {
                source = e.source or "automatic",
                policy = e.policy,
                reason = e.reason or "restore",
                reconciliation_mode = mode,
            })
            local policy = e.policy
            if not policy then
                if e.list == "scanner_drop" then policy = "scanner"
                elseif e.list == "cc_drop" then policy = "cc"
                else policy = "manual" end
            end
            sm.upsert(e.ip, policy, e.state or "installed", e.evidence or {}, {
                list = e.list,
                family = e.family,
                installed_at = e.installed_at,
                expires_at = e.expires_at,
                source = e.source or "automatic",
                reconciliation_mode = mode,
            })
            restored = restored + 1
            ::continue::
        end
    end
    ngx.log(ngx.INFO, "kernel_blocking: restored ", restored, " desired entries")
end

function _M.persist()
    if worker_id() ~= 0 then return false, "not_worker0" end
    local got, token = acquire_lease(PERSIST_LEASE, DEFAULT_LEASE_TTL.persist)
    if not got then return false, "lease_busy" end

    local ok, err = pcall(function()
        local entries = {}
        local cursor = 0
        repeat
            local page = desired.list_desired(cursor, 500)
            for _, e in ipairs(page.entries or {}) do
                entries[#entries + 1] = {
                    ip = e.ip,
                    family = e.family,
                    list = e.list,
                    expires_at = e.expires_at,
                    source = e.source,
                    policy = e.policy,
                    reason = e.reason,
                    evidence = e.evidence,
                    reconciliation_mode = e.reconciliation_mode or
                        (e.source == "manual" and "manual" or "ensure"),
                }
            end
            cursor = page.next_cursor
        until not cursor

        -- Also capture installed SM entries missing from desired (defensive).
        cursor = 0
        repeat
            local page = sm.list(cursor, 500, "installed")
            for _, e in ipairs(page.entries or {}) do
                if e.list and e.ip then
                    local family = e.family or "ipv4"
                    if not desired.get_desired(e.ip, family, e.list) then
                        entries[#entries + 1] = {
                            ip = e.ip,
                            family = family,
                            list = e.list,
                            expires_at = e.expires_at,
                            source = e.source,
                            policy = e.policy,
                            state = e.state,
                            reconciliation_mode = e.reconciliation_mode or
                                (e.source == "manual" and "manual" or "ensure"),
                        }
                    end
                end
            end
            cursor = page.next_cursor
        until not cursor

        local payload = {
            version = STATE_VERSION,
            saved_at = ngx.time(),
            lifecycle = lifecycle.get_state(),
            entries = entries,
        }
        local path = state_path()
        local tmp = path .. ".tmp"
        local encoded = json.encode(payload, { indent = true })
        local f, ferr = io.open(tmp, "w")
        if not f then
            error("open tmp failed: " .. tostring(ferr))
        end
        f:write(encoded)
        f:close()
        local rok, rerr = os.rename(tmp, path)
        if not rok then
            error("rename failed: " .. tostring(rerr))
        end
    end)

    release_lease(PERSIST_LEASE, token)
    if not ok then
        ngx.log(ngx.ERR, "kernel_blocking.persist failed: ", err)
        return false, err
    end
    return true
end

function _M.bootstrap()
    if worker_id() ~= 0 then return { skipped = "not_worker0" } end
    local kb = config.kernel_ip_blocking
    if not kb or kb.enabled ~= true then
        return { skipped = "disabled" }
    end

    local executor = require "core.kernel_blocking.executor"
    local scope_binding = require "core.kernel_blocking.scope_binding"
    local exec = executor.get_executor()
    local result = {
        probe = nil, ensure_base = false, allow = false, health = nil,
        scope = scope_binding.status_view(),
    }

    local ok_p, probe = pcall(function() return exec.probe() end)
    result.probe = ok_p and probe or { error = tostring(probe) }

    local ok_h, health = pcall(function() return exec.health() end)
    result.health = ok_h and health or { state = "unreachable" }

    if not ok_h or not health or health.state ~= "ok" then
        scope_binding.invalidate("helper_unavailable")
        return result
    end

    -- Always re-bind scope on bootstrap (Design §8.3.4 / §10.3).
    local call_ok, ensure_ok, ensure_err = pcall(function()
        return exec.ensure_base(kb)
    end)
    if not call_ok then
        ensure_err = ensure_ok
        ensure_ok = false
    end
    result.ensure_base = ensure_ok and true or false
    if not result.ensure_base then
        ngx.log(ngx.WARN, "kernel_blocking bootstrap ensure_base failed: ", tostring(ensure_err))
        scope_binding.invalidate(tostring(ensure_err or "ensure_base_failed"))
        result.scope = scope_binding.status_view()
        return result
    end

    local wlg = require "core.kernel_blocking.whitelist_generation"
    local ok_a, aerr = pcall(function() return wlg.push_allow_snapshot() end)
    result.allow = ok_a
    if not ok_a then
        ngx.log(ngx.WARN, "kernel_blocking bootstrap allow snapshot failed: ", tostring(aerr))
    end
    result.scope = scope_binding.status_view()
    return result
end

function _M.process_candidates(now)
    local got, token = acquire_lease(BATCH_LEASE, DEFAULT_LEASE_TTL.batch)
    if not got then return { skipped = "lease_busy" } end

    local ok, err = pcall(function()
        local promotion = require "core.kernel_blocking.promotion"
        promotion.process_candidates(now or ngx.time())
        -- Dispatch flush is independently leased (Design §10.3).
        _M.flush_dispatch_queue(now)
    end)
    release_lease(BATCH_LEASE, token)
    if not ok then
        ngx.log(ngx.ERR, "kernel_blocking.process_candidates failed: ", err)
        return { error = tostring(err) }
    end
    return { ok = true }
end

function _M.flush_dispatch_queue(_now)
    -- In-process path currently installs inline in promotion. This hook is the
    -- design-required extension point for bounded async dispatch/retry.
    local got, token = acquire_lease(DISPATCH_LEASE, DEFAULT_LEASE_TTL.dispatch)
    if not got then return { skipped = "lease_busy" } end

    local ok, result = pcall(function()
        return { ok = true, depth = 0 }
    end)
    release_lease(DISPATCH_LEASE, token)
    if not ok then
        ngx.log(ngx.ERR, "kernel_blocking.flush_dispatch_queue failed: ", result)
        return { error = tostring(result) }
    end
    return result
end

function _M.reconcile(now)
    local got, token = acquire_lease(RECONCILE_LEASE, DEFAULT_LEASE_TTL.reconcile)
    if not got then return { skipped = "lease_busy" } end
    local recon = require "core.kernel_blocking.reconciliation"
    local ok, result = pcall(function()
        return recon.reconcile(now or ngx.time())
    end)
    release_lease(RECONCILE_LEASE, token)
    if not ok then
        ngx.log(ngx.ERR, "kernel_blocking.reconcile failed: ", result)
        return { error = tostring(result) }
    end
    -- Cache compact last-reconcile summary for dashboard.
    pcall(function()
        local s = ngx.shared[LEASE_DICT]
        if s and type(result) == "table" then
            s:set("kb:last_reconcile", json.encode({
                at = ngx.time(),
                dry_run = result.dry_run,
                to_add = #(result.to_add or {}),
                to_update = #(result.to_update or {}),
                to_remove = #(result.to_remove or {}),
                applied_add = result.applied_add or 0,
                applied_remove = result.applied_remove or 0,
                failed = result.failed or 0,
                skipped_preserve = result.skipped_preserve or 0,
                health = result.health,
                skipped = result.skipped,
            }), 86400)
        end
    end)
    pcall(_M.update_metrics, result)
    return result
end

function _M.status(_)
    -- Sample bucket history for trend chart (throttled internally).
    _M.sample_bucket_history()
    local token_bucket = require "core.kernel_blocking.token_bucket"
    local enforce_status = token_bucket.enforce_status()
    local observe_status = token_bucket.observe_status()
    local kb = config.kernel_ip_blocking or {}
    local executor = require "core.kernel_blocking.executor"
    local exec = executor.get_executor()
    local health_ok, health = pcall(function() return exec.health() end)
    if not health_ok then
        health = { state = "unreachable", error = tostring(health) }
    end

    local installed = sm.count("installed")
    local active_auto = 0
    do
        local page = sm.list(0, 500, "installed")
        for _, e in ipairs(page.entries or {}) do
            if e.policy == "scanner" or e.policy == "cc" then
                active_auto = active_auto + 1
            end
        end
    end

    local matrix = readiness.compute({
        health = health,
        active_auto_entries = active_auto,
        lifecycle = lifecycle.get_state(),
    })

    local wlg = require "core.kernel_blocking.whitelist_generation"
    local epoch, seq = wlg.get_generation()

    local last_reconcile = nil
    local locks = ngx.shared.vn_locks
    if locks then
        local raw = locks:get("kb:last_reconcile")
        if raw then
            local ok, t = pcall(json.decode, raw)
            if ok and type(t) == "table" then last_reconcile = t end
        end
    end

    -- Enrich configured with scope fields for dashboard.
    matrix.configured.protected_addresses = kb.protected_addresses or {}
    matrix.configured.protected_ports = kb.protected_ports or {}
    matrix.configured.helper_socket = kb.helper_socket
    matrix.configured.batch_interval = kb.batch_interval
    matrix.configured.reconcile_interval = kb.reconcile_interval
    matrix.configured.promotion_rate_limit = kb.promotion_rate_limit

    return {
        configured = matrix.configured,
        effective = matrix.effective,
        health = health,
        helper_instance_id = health and (health.instance_id or health.helper_instance_id) or nil,
        migration = matrix.migration,
        counter_namespace = matrix.counter_namespace,
        cutover_epoch = matrix.cutover_epoch,
        cc_rules = matrix.cc_rules,
        lifecycle = matrix.lifecycle,
        whitelist_generation = {
            control_plane = { epoch = epoch, sequence = seq },
            helper_installed = health and health.allow_generation or nil,
        },
        promotion_bucket = {
            enforce = {
                tokens_available = enforce_status.tokens or 0,
                tokens_microunits = enforce_status.tokens_microunits or 0,
                limit = enforce_status.limit or 0,
                interval = enforce_status.interval or 0,
                burst = enforce_status.burst or 0,
                last_refill_ms = enforce_status.last_refill_ms or 0,
            },
            observe = {
                tokens_available = observe_status.tokens or 0,
                tokens_microunits = observe_status.tokens_microunits or 0,
                limit = observe_status.limit or 0,
                interval = observe_status.interval or 0,
                burst = observe_status.burst or 0,
                last_refill_ms = observe_status.last_refill_ms or 0,
            },
            rate_limited_recent = sm.count("rate_limited"),
        },
        counters = {
            candidates = math.max(sm.count() - installed, 0),
            installed = installed,
            installed_scanner = sm.count("installed", "scanner"),
            installed_cc = sm.count("installed", "cc"),
            installed_manual = sm.count("installed", "manual"),
            rejected = sm.count("rejected"),
            degraded = sm.count("degraded"),
            rate_limited = sm.count("rate_limited"),
            paused = sm.count("scope_validation_pending"),
            desired = desired.count_desired(),
            active_auto_while_disabled = (kb.enabled ~= true) and active_auto or 0,
            drift = last_reconcile and (
                (last_reconcile.to_add or 0) + (last_reconcile.to_remove or 0)
            ) or 0,
        },
        last_reconcile = last_reconcile,
        dispatch_queue = { depth = 0 },
        scheduler_leases = _M.lease_status(),
        ipc = (function()
            local ok, client = pcall(require, "core.kernel_blocking.ipc_client")
            if ok and client and client.stats then return client.stats() end
            return nil
        end)(),
        scope_binding = (function()
            local ok, sb = pcall(require, "core.kernel_blocking.scope_binding")
            if ok and sb then return sb.status_view() end
            return { validated = false, reason = "module_missing" }
        end)(),
    }
end

-- Bucket history for trend chart (Design §12.2).
-- Stores sampled token balance in a circular buffer in vn_locks.
local BUCKET_HISTORY_KEY = "kb:bucket_history"
local BUCKET_HISTORY_MAX = 288  -- 24h at 5min intervals

function _M.sample_bucket_history()
    local locks = ngx.shared.vn_locks
    if not locks then return end
    -- Throttle: at most one sample per 5 minutes.
    local last_raw = locks:get(BUCKET_HISTORY_KEY .. ":last")
    local now = ngx.time()
    if last_raw and (now - tonumber(last_raw) or 0) < 300 then return end
    locks:set(BUCKET_HISTORY_KEY .. ":last", tostring(now), 600)

    local tb = require "core.kernel_blocking.token_bucket"
    local est = tb.enforce_status()
    local ost = tb.observe_status()
    local sample = {
        t = now,
        enforce_tokens = est.tokens or 0,
        observe_tokens = ost.tokens or 0,
    }
    local raw = locks:get(BUCKET_HISTORY_KEY)
    local history = {}
    if raw then
        local ok, t = pcall(json.decode, raw)
        if ok and type(t) == "table" then history = t end
    end
    history[#history + 1] = sample
    while #history > BUCKET_HISTORY_MAX do
        table.remove(history, 1)
    end
    locks:set(BUCKET_HISTORY_KEY, json.encode(history), 0)
end

function _M.get_bucket_history()
    local locks = ngx.shared.vn_locks
    if not locks then return {} end
    local raw = locks:get(BUCKET_HISTORY_KEY)
    if not raw then return {} end
    local ok, t = pcall(json.decode, raw)
    if ok and type(t) == "table" then return t end
    return {}
end

-- Drift diff: desired vs actual (Design §12.2).
function _M.get_diff()
    local desired_map = {}
    local actual = {}
    local cursor = 0
    repeat
        local page = desired.list_desired(cursor, 500)
        for _, e in ipairs(page.entries or {}) do
            local key = (e.list or "") .. ":" .. (e.family or "ipv4") .. ":" .. (e.ip or "")
            desired_map[key] = e
        end
        cursor = page.next_cursor
    until not cursor

    local exec = require("core.kernel_blocking.executor").get_executor()
    local DROP_LISTS = { "scanner_drop", "cc_drop", "manual_drop" }
    local FAMILIES = { "ipv4", "ipv6" }
    for _, list in ipairs(DROP_LISTS) do
        for _, family in ipairs(FAMILIES) do
            local c2 = 0
            repeat
                local page = exec.list(list, family, c2)
                for _, e in ipairs(page.entries or {}) do
                    local key = list .. ":" .. family .. ":" .. (e.ip or "")
                    actual[key] = { list = list, family = family, ip = e.ip, ttl = e.TTL }
                end
                c2 = page.next_cursor
            until not c2
        end
    end

    local missing_in_kernel = {}  -- desired but not in kernel
    local orphan_in_kernel = {}   -- in kernel but not desired
    for key, d in pairs(desired_map) do
        if not actual[key] then
            missing_in_kernel[#missing_in_kernel + 1] = {
                ip = d.ip, list = d.list, family = d.family,
                expires_at = d.expires_at, source = d.source,
            }
        end
    end
    for key, a in pairs(actual) do
        if not desired_map[key] then
            orphan_in_kernel[#orphan_in_kernel + 1] = {
                ip = a.ip, list = a.list, family = a.family,
            }
        end
    end

    return {
        missing_in_kernel = missing_in_kernel,
        orphan_in_kernel = orphan_in_kernel,
        desired_count = desired.count_desired(),
        actual_count = (function()
            local n = 0
            for _ in pairs(actual) do n = n + 1 end
            return n
        end)(),
    }
end

function _M.update_metrics(reconcile_result)
    local metrics = require "core.metrics"
    local st = _M.status()
    metrics.gauge("verynginx_kernel_block_candidates", st.counters.candidates)
    metrics.gauge("verynginx_kernel_block_installed", st.counters.installed)
    metrics.gauge("verynginx_kernel_block_desired", st.counters.desired)
    metrics.gauge("verynginx_kernel_block_promotion_tokens",
        st.promotion_bucket.tokens_available or 0)
    metrics.gauge("verynginx_kernel_block_degraded", st.counters.degraded)
    if reconcile_result and not reconcile_result.skipped then
        metrics.gauge("verynginx_kernel_block_reconcile_drift",
            #(reconcile_result.to_add or {}) + #(reconcile_result.to_remove or {}))
        if reconcile_result.applied_add then
            metrics.incr("verynginx_kernel_block_operations_total",
                reconcile_result.applied_add, { operation = "add", result = "ok" })
        end
        if reconcile_result.applied_remove then
            metrics.incr("verynginx_kernel_block_operations_total",
                reconcile_result.applied_remove, { operation = "delete", result = "ok" })
        end
        if reconcile_result.failed and reconcile_result.failed > 0 then
            metrics.incr("verynginx_kernel_block_operations_total",
                reconcile_result.failed, { operation = "reconcile", result = "failed" })
        end
    end
end

return _M
