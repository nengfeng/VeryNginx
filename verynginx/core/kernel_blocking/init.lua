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
local PERSIST_LEASE = "kb:lease:persist"
local RECONCILE_LEASE = "kb:lease:reconcile"
local DISPATCH_LEASE = "kb:lease:dispatch"

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
    local token = tostring(ngx.time()) .. ":" .. tostring(worker_id()) .. ":" .. tostring(math.random(1, 1e9))
    local ok = s:add(name, token, ttl or 30)
    if ok then return true, token end
    return false, "busy"
end

local function release_lease(name, token)
    local s = ngx.shared[LEASE_DICT]
    if not s then return end
    if s:get(name) == token then
        s:delete(name)
    end
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
    local got, token = acquire_lease(PERSIST_LEASE, 30)
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
    local exec = executor.get_executor()
    local result = { probe = nil, ensure_base = false, allow = false, health = nil }

    local ok_p, probe = pcall(function() return exec.probe() end)
    result.probe = ok_p and probe or { error = tostring(probe) }

    local ok_h, health = pcall(function() return exec.health() end)
    result.health = ok_h and health or { state = "unreachable" }

    if not ok_h or not health or health.state ~= "ok" then
        return result
    end

    local ok_b, berr = pcall(function() return exec.ensure_base(kb) end)
    result.ensure_base = ok_b and berr ~= false
    if not result.ensure_base then
        ngx.log(ngx.WARN, "kernel_blocking bootstrap ensure_base failed: ", tostring(berr))
    end

    local wlg = require "core.kernel_blocking.whitelist_generation"
    local ok_a, aerr = pcall(function() return wlg.push_allow_snapshot() end)
    result.allow = ok_a
    if not ok_a then
        ngx.log(ngx.WARN, "kernel_blocking bootstrap allow snapshot failed: ", tostring(aerr))
    end
    return result
end

function _M.process_candidates(now)
    local promotion = require "core.kernel_blocking.promotion"
    promotion.process_candidates(now or ngx.time())
    _M.flush_dispatch_queue(now)
end

function _M.flush_dispatch_queue(_now)
    -- In-process path currently installs inline in promotion. This hook is the
    -- design-required extension point for bounded async dispatch/retry.
    local got, token = acquire_lease(DISPATCH_LEASE, 10)
    if not got then return { skipped = "lease_busy" } end
    release_lease(DISPATCH_LEASE, token)
    return { ok = true, depth = 0 }
end

function _M.reconcile(now)
    local got, token = acquire_lease(RECONCILE_LEASE, 60)
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

    local locks = ngx.shared.vn_locks
    local enforce_bucket = { tokens = 0, last_refill = 0, source = "cold_empty" }
    local observe_bucket = { tokens = 0, last_refill = 0, source = "cold_empty" }
    if locks then
        local eraw = locks:get("kb:enforce_bucket:state")
        if eraw then
            local ok, t = pcall(json.decode, eraw)
            if ok and type(t) == "table" then enforce_bucket = t end
        end
        local oraw = locks:get("kb:observe_bucket:state")
        if oraw then
            local ok, t = pcall(json.decode, oraw)
            if ok and type(t) == "table" then observe_bucket = t end
        end
    end

    local wlg = require "core.kernel_blocking.whitelist_generation"
    local epoch, seq = wlg.get_generation()

    local last_reconcile = nil
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
                tokens_available = enforce_bucket.tokens or 0,
                last_refill = enforce_bucket.last_refill or 0,
                source = enforce_bucket.source or "unknown",
            },
            observe = {
                tokens_available = observe_bucket.tokens or 0,
                last_refill = observe_bucket.last_refill or 0,
                source = observe_bucket.source or "unknown",
            },
            tokens_available = enforce_bucket.tokens or 0,
            last_refill = enforce_bucket.last_refill or 0,
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
