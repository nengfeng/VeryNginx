-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking lifecycle: activation generations, evidence
--             cutoffs, preserve_only transitions, and bucket resets.
--             Design §10.5.

local _M = {}

local json = require "dkjson"
local desired = require "core.kernel_blocking.desired_state"
local sm = require "core.kernel_blocking.state_machine"

local LOCKS = "vn_locks"
local STATE_KEY = "kb:lifecycle:state"

local function locks()
    return ngx.shared[LOCKS]
end

local function default_state(now)
    now = now or ngx.time()
    return {
        global_activation_generation = 1,
        policy_generation = { scanner = 1, cc = 1 },
        evidence_not_before = now,
        policy_evidence_not_before = { scanner = now, cc = now },
        digests = {
            global = "",
            scanner = "",
            cc = "",
        },
        last_transition_at = now,
        last_transition = "init",
    }
end

function _M.get_state()
    local s = locks()
    if not s then return default_state() end
    local raw = s:get(STATE_KEY)
    if not raw then
        local st = default_state()
        s:add(STATE_KEY, json.encode(st), 0)
        return st
    end
    local ok, st = pcall(json.decode, raw)
    if not ok or type(st) ~= "table" then
        return default_state()
    end
    st.policy_generation = st.policy_generation or { scanner = 1, cc = 1 }
    st.policy_evidence_not_before = st.policy_evidence_not_before or {
        scanner = st.evidence_not_before or ngx.time(),
        cc = st.evidence_not_before or ngx.time(),
    }
    st.digests = st.digests or { global = "", scanner = "", cc = "" }
    return st
end

function _M.set_state(st)
    local s = locks()
    if not s or type(st) ~= "table" then return false end
    s:set(STATE_KEY, json.encode(st), 0)
    return true
end

function _M.ensure_initialized()
    local s = locks()
    if not s then return default_state() end
    local existing = s:get(STATE_KEY)
    if existing then
        return _M.get_state()
    end
    local st = default_state()
    s:add(STATE_KEY, json.encode(st), 0)
    return st
end

local function reset_buckets()
    -- Must use the same keys as token_bucket (Design §6.2 / §10.5).
    local ok, tb = pcall(require, "core.kernel_blocking.token_bucket")
    if ok and tb and tb.reset_buckets then
        tb.reset_buckets()
        return
    end
end

local function mark_auto_preserve(policy, reason)
    local cursor = 0
    repeat
        local page = sm.list(cursor, 500, "installed", policy)
        for _, e in ipairs(page.entries or {}) do
            if e.list then
                local family = e.family or "ipv4"
                local d = desired.get_desired(e.ip, family, e.list)
                local ttl = 0
                if e.expires_at then
                    ttl = math.max(e.expires_at - ngx.time(), 1)
                elseif d and d.expires_at then
                    ttl = math.max(d.expires_at - ngx.time(), 1)
                end
                desired.set_desired(e.ip, family, e.list, e.evidence or {}, ttl, {
                    source = e.source or "automatic",
                    policy = policy,
                    reason = reason or "preserve_only",
                    reconciliation_mode = "preserve_only",
                })
                sm.transition(e.ip, policy, e.state or "installed", {
                    reconciliation_mode = "preserve_only",
                    reason = reason or "preserve_only",
                })
            end
        end
        cursor = page.next_cursor
    until not cursor

    -- Suspend non-installed automatic candidates so they are not replayed.
    cursor = 0
    repeat
        local page = sm.list(cursor, 500, nil, policy)
        for _, e in ipairs(page.entries or {}) do
            if e.state ~= "installed" and e.state ~= "cleared" and e.state ~= "expired" then
                sm.transition(e.ip, policy, "rejected", {
                    reason = "suspended_disabled",
                    previous_state = e.state,
                })
            end
        end
        cursor = page.next_cursor
    until not cursor
end

local function digest_of(tbl)
    if type(tbl) ~= "table" then return "" end
    local ok, encoded = pcall(json.encode, tbl)
    if not ok or not encoded then return "" end
    if ngx.md5 then
        return ngx.md5(encoded)
    end
    return tostring(#encoded) .. ":" .. encoded:sub(1, 32)
end

local function kb_digest_parts(kb)
    kb = kb or {}
    return {
        global = digest_of({
            enabled = kb.enabled,
            mode = kb.mode,
            topology = kb.topology,
            fail_policy = kb.fail_policy,
            scope = kb.scope,
            protected_addresses = kb.protected_addresses,
            protected_ports = kb.protected_ports,
            ipv4 = kb.ipv4,
            ipv6 = kb.ipv6,
            emergency_pause = kb.emergency_pause,
        }),
        scanner = digest_of(kb.scanner or {}),
        cc = digest_of(kb.cc or {}),
    }
end

-- Apply config transition effects based on old/new kernel_ip_blocking sections.
function _M.on_config_activated(old_cfg, new_cfg)
    old_cfg = old_cfg or {}
    new_cfg = new_cfg or {}
    local old_kb = old_cfg.kernel_ip_blocking or {}
    local new_kb = new_cfg.kernel_ip_blocking or {}
    local st = _M.ensure_initialized()
    local now = ngx.time()
    local changed = false
    local reasons = {}

    local old_d = kb_digest_parts(old_kb)
    local new_d = kb_digest_parts(new_kb)

    local global_changed = old_d.global ~= new_d.global
        or (old_kb.enabled == true and new_kb.enabled ~= true)
        or (old_kb.enabled ~= true and new_kb.enabled == true)
        or (old_kb.mode or "observe") ~= (new_kb.mode or "observe")

    if global_changed then
        st.global_activation_generation = (st.global_activation_generation or 1) + 1
        st.evidence_not_before = now
        reset_buckets()
        changed = true
        reasons[#reasons + 1] = "global_transition"

        if old_kb.enabled == true and new_kb.enabled ~= true then
            mark_auto_preserve("scanner", "global_disabled")
            mark_auto_preserve("cc", "global_disabled")
            reasons[#reasons + 1] = "enabled_false_preserve_only"
        elseif (old_kb.mode or "observe") == "enforce" and (new_kb.mode or "observe") == "observe" then
            mark_auto_preserve("scanner", "mode_observe")
            mark_auto_preserve("cc", "mode_observe")
            reasons[#reasons + 1] = "mode_observe_preserve_only"
        end
    end

    if old_d.scanner ~= new_d.scanner then
        st.policy_generation.scanner = (st.policy_generation.scanner or 1) + 1
        st.policy_evidence_not_before.scanner = now
        changed = true
        reasons[#reasons + 1] = "scanner_policy_transition"
        if (old_kb.scanner and old_kb.scanner.enabled) and not (new_kb.scanner and new_kb.scanner.enabled) then
            mark_auto_preserve("scanner", "scanner_disabled")
        else
            -- threshold/config change: installed become preserve_only
            mark_auto_preserve("scanner", "scanner_policy_changed")
        end
    end

    if old_d.cc ~= new_d.cc then
        st.policy_generation.cc = (st.policy_generation.cc or 1) + 1
        st.policy_evidence_not_before.cc = now
        changed = true
        reasons[#reasons + 1] = "cc_policy_transition"
        local old_ready = old_kb.cc and old_kb.cc.enforce_ready
        local new_ready = new_kb.cc and new_kb.cc.enforce_ready
        if old_ready and not new_ready then
            mark_auto_preserve("cc", "cc_not_enforce_ready")
        elseif (old_kb.cc and old_kb.cc.enabled) and not (new_kb.cc and new_kb.cc.enabled) then
            mark_auto_preserve("cc", "cc_disabled")
        else
            mark_auto_preserve("cc", "cc_policy_changed")
        end
    end

    st.digests = new_d
    if changed then
        st.last_transition_at = now
        st.last_transition = table.concat(reasons, ",")
        _M.set_state(st)
        pcall(function()
            local audit = require "core.audit"
            audit.log("kernel_blocking.lifecycle", st.last_transition)
        end)
        pcall(function()
            local metrics = require "core.metrics"
            metrics.incr("verynginx_kernel_block_lifecycle_transitions_total", 1, {
                reason = reasons[1] or "unknown",
            })
        end)
    else
        -- keep digests current even without generation bump
        st.digests = new_d
        _M.set_state(st)
    end
    return st, reasons
end

function _M.evidence_allowed(policy, event_ts)
    local st = _M.get_state()
    event_ts = event_ts or ngx.time()
    if event_ts < (st.evidence_not_before or 0) then
        return false, "global_cutoff"
    end
    local pcut = st.policy_evidence_not_before and st.policy_evidence_not_before[policy]
    if pcut and event_ts < pcut then
        return false, "policy_cutoff"
    end
    return true, nil
end

function _M.import_state(snapshot_state)
    if type(snapshot_state) ~= "table" then return false end
    local st = default_state()
    for k, v in pairs(snapshot_state) do
        st[k] = v
    end
    return _M.set_state(st)
end

return _M
