-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking effective-state / readiness matrix (Design §11.5).

local _M = {}

local function push_reason(list, code)
    if not code then return end
    for _, c in ipairs(list) do
        if c == code then return end
    end
    list[#list + 1] = code
end

local function helper_state(health)
    if type(health) ~= "table" then
        return "unavailable", { "helper_unavailable" }
    end
    if health.state == "ok" then
        return "ok", {}
    end
    return health.state or "unavailable", { "helper_unavailable" }
end

local function family_ok(kb_cfg, family)
    if family == "ipv6" then
        return kb_cfg.ipv6 and kb_cfg.ipv6.enabled == true
    end
    return not kb_cfg.ipv4 or kb_cfg.ipv4.enabled ~= false
end

function _M.compute(opts)
    opts = opts or {}
    local config = require "core.config"
    local kb = config.kernel_ip_blocking or {}
    local health = opts.health
    local active_auto = opts.active_auto_entries or 0
    local lifecycle = opts.lifecycle
    if not lifecycle then
        local ok, life = pcall(require, "core.kernel_blocking.lifecycle")
        if ok then lifecycle = life.get_state() end
    end
    lifecycle = lifecycle or {}

    local helper_status, helper_reasons = helper_state(health)

    local configured = {
        enabled = kb.enabled == true,
        mode = kb.mode or "observe",
        emergency_pause = kb.emergency_pause == true,
        topology = kb.topology or "unknown",
        shadow = kb.shadow == true,
        scanner_enabled = not kb.scanner or kb.scanner.enabled ~= false,
        cc_enabled = not kb.cc or kb.cc.enabled ~= false,
        cc_enforce_ready = kb.cc and kb.cc.enforce_ready == true,
        cc_rule_ids = (kb.cc and kb.cc.rule_ids) or {},
    }

    local global_mode = "disabled"
    if configured.enabled then
        global_mode = configured.mode == "enforce" and "enforce" or "observe"
    end

    local global_reasons = {}
    local global_reachable = false
    if global_mode == "disabled" then
        push_reason(global_reasons, "global_disabled")
    elseif global_mode == "observe" then
        push_reason(global_reasons, "global_observe")
    else
        global_reachable = true
        if helper_status ~= "ok" then
            global_reachable = false
            for _, r in ipairs(helper_reasons) do push_reason(global_reasons, r) end
        end
        if configured.topology ~= "direct" then
            global_reachable = false
            push_reason(global_reasons, "topology")
        end
        if configured.emergency_pause then
            global_reachable = false
            push_reason(global_reasons, "emergency_pause")
        end
        if not family_ok(kb, "ipv4") and not family_ok(kb, "ipv6") then
            global_reachable = false
            push_reason(global_reasons, "family_disabled")
        end
    end
    if not configured.enabled and active_auto > 0 then
        push_reason(global_reasons, "disabled_with_active_entries")
    end

    -- Scanner effective mode
    local scanner_mode = "disabled"
    local scanner_reasons = {}
    local scanner_reachable = false
    if global_mode == "disabled" then
        push_reason(scanner_reasons, "global_disabled")
    elseif not configured.scanner_enabled then
        push_reason(scanner_reasons, "scanner_disabled")
    elseif global_mode == "observe" then
        scanner_mode = "observe"
        push_reason(scanner_reasons, "global_observe")
    else
        scanner_mode = "enforce"
        scanner_reachable = global_reachable
        for _, r in ipairs(global_reasons) do
            if r ~= "global_observe" and r ~= "global_disabled" then
                push_reason(scanner_reasons, r)
            end
        end
        if not family_ok(kb, "ipv4") then
            scanner_reachable = false
            push_reason(scanner_reasons, "family_disabled")
        end
    end

    -- CC effective mode matrix
    local cc_mode = "disabled"
    local cc_reasons = {}
    local cc_reachable = false
    local rule_ids = configured.cc_rule_ids
    if global_mode == "disabled" then
        push_reason(cc_reasons, "global_disabled")
    elseif not configured.cc_enabled then
        push_reason(cc_reasons, "cc_disabled")
    elseif type(rule_ids) ~= "table" or #rule_ids == 0 then
        push_reason(cc_reasons, "no_rule_ids")
    elseif global_mode == "observe" then
        cc_mode = "observe"
        push_reason(cc_reasons, "global_observe")
    elseif not configured.cc_enforce_ready then
        cc_mode = "observe"
        push_reason(cc_reasons, "cc_not_enforce_ready")
    else
        cc_mode = "enforce"
        cc_reachable = global_reachable
        for _, r in ipairs(global_reasons) do
            if r ~= "global_observe" and r ~= "global_disabled" then
                push_reason(cc_reasons, r)
            end
        end
    end

    -- Frequency migration / v2 cutover gates for CC install
    local migration = { status = "unknown" }
    local cutover = false
    local ok_freq, freq = pcall(require, "core.frequency")
    if ok_freq and freq then
        migration = freq.get_migration_status() or migration
        cutover = freq.is_cutover_complete and freq.is_cutover_complete() or false
    end
    if cc_mode == "enforce" then
        if migration.status ~= "completed" and migration.status ~= "no_rules" then
            cc_reachable = false
            push_reason(cc_reasons, "counter_namespace_not_v2")
        elseif not cutover and migration.status == "completed" then
            cc_reachable = false
            push_reason(cc_reasons, "counter_namespace_not_v2")
        end
    end

    local cc_rules = {}
    for _, rid in ipairs(rule_ids) do
        local ref_valid = true
        if ok_freq and freq and freq.id_to_index_map then
            local map = freq.id_to_index_map()
            ref_valid = map[rid] ~= nil
        end
        local reasons = {}
        if not ref_valid then push_reason(reasons, "invalid_rule_ref") end
        if not cutover then push_reason(reasons, "counter_namespace_not_v2") end
        cc_rules[#cc_rules + 1] = {
            rule_id = rid,
            reference_valid = ref_valid,
            counter_namespace = cutover and "v2" or "v1",
            cutover_epoch = (ngx.shared.frequency_limit and ngx.shared.frequency_limit:get("fl:v2:cutover_epoch")) or nil,
            effective_mode = cc_mode,
            install_reachable = cc_reachable and ref_valid or false,
            reason_codes = reasons,
        }
    end

    return {
        configured = configured,
        effective = {
            global_mode = global_mode,
            global_install_reachable = global_reachable,
            reason_codes = global_reasons,
            scanner = {
                mode = scanner_mode,
                install_reachable = scanner_reachable,
                reason_codes = scanner_reasons,
            },
            cc = {
                mode = cc_mode,
                install_reachable = cc_reachable,
                reason_codes = cc_reasons,
            },
        },
        migration = migration,
        counter_namespace = cutover and "v2" or "v1",
        cutover_epoch = (ngx.shared.frequency_limit and ngx.shared.frequency_limit:get("fl:v2:cutover_epoch")) or nil,
        cc_rules = cc_rules,
        lifecycle = {
            global_activation_generation = lifecycle.global_activation_generation,
            policy_generation = lifecycle.policy_generation,
            evidence_not_before = lifecycle.evidence_not_before,
            policy_evidence_not_before = lifecycle.policy_evidence_not_before,
            last_transition = lifecycle.last_transition,
            last_transition_at = lifecycle.last_transition_at,
        },
        helper = {
            state = helper_status,
            reason_codes = helper_reasons,
        },
    }
end

return _M
