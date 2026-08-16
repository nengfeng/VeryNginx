-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : frequency limit plugin - rate limit requests by matcher rules
--             Supports v1 (legacy) and v2 (post-migration) key namespaces.
--             v2 enables CC violation evidence recording for kernel blocking.

local _M = {}

_M.name = "frequency_limit"
_M.priority = 200
_M.default_enable = true
_M.critical = true

local config = require "core.config"
local matcher = require "matcher.init"
local limiter = require "plugin.frequency_limit.limiter"
local ip_enc = require "core.kernel_blocking.ip_encoding"
local ev = require "core.kernel_blocking.evidence"

-- Check if v2 counter namespace is active (migration complete + cutover done).
-- v2 is enabled when:
--   1. All frequency rules have stable IDs (migration complete)
--   2. The cutover has been performed (cutover_epoch recorded in shared state)
--
-- Cached per-worker with generation invalidation. Config saves bump
-- fl:v2:config_generation in shared dict; worker checks generation and
-- recomputes only when it changes (avoids O(#rules) scan per request).
local _v2_cache = { generation = -1, active = false }

local function is_v2_active()
    local s = ngx.shared.frequency_limit
    if not s then
        _v2_cache = { generation = -1, active = false }
        return false
    end

    local gen = s:get("fl:v2:config_generation") or 0
    if _v2_cache.generation == gen then
        return _v2_cache.active
    end

    -- Recompute
    local rules = config.rule and config.rule.frequency_limit
    local active = false
    if rules and type(rules) == "table" and #rules > 0 then
        local all_have_id = true
        for _, rule in ipairs(rules) do
            if not rule or not rule.id or rule.id == "" then
                all_have_id = false
                break
            end
        end
        if all_have_id and s:get("fl:v2:cutover_epoch") ~= nil then
            active = true
        end
    end

    _v2_cache = { generation = gen, active = active }
    return active
end

function _M.on_access(ctx)
    local rules = config.rule.frequency_limit
    if not rules then
        return
    end

    local shared = ngx.shared.frequency_limit
    if not shared then
        return
    end

    local v2 = is_v2_active()

    for _, rule in ipairs(rules) do
        if rule.enable == false then
            goto continue
        end

        local matcher_def = matcher.resolve(rule)
        if not matcher_def then
            goto continue
        end

        if matcher.test(matcher_def, ctx) then
            local limit = rule.limit or 60
            local window = rule.window or 60
            local key
            if v2 then
                local enc_id = ip_enc.encode_rule_id(rule.id)
                local enc_dim = limiter.build_key_v2(rule.key or "ip", ctx)
                key = "fl:v2:count:" .. enc_id .. ":" .. enc_dim
            else
                key = limiter.build_key(rule.key or "ip", ctx)
            end
            local current = shared:incr(key, 1, 0, window)

            if current and current > limit then
                -- Record CC violation evidence on FIRST transition past limit
                -- (current == limit + 1 means this request just crossed the threshold)
                if v2 and current == limit + 1 then
                    local ip = ip_enc.canonical_ip(ctx.request.remote_addr)
                    ev.record_cc_violation_evidence(rule.id, ip, window)
                end

                ctx.set_data(ctx, "frequency_limit:limited", true)
                ctx.set_action(ctx, "block", {
                    code = rule.code or 429,
                    response = rule.response or "Too Many Requests"
                })
                return
            end
        end
        ::continue::
    end
end

return _M
