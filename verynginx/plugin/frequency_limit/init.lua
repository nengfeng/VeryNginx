-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : frequency limit plugin - rate limit requests by matcher rules
--             One counter namespace; CC violation evidence is recorded for the
--             rules the kernel-blocking CC policy references.

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
local dict_guard = require "core.dict_guard"

-- Rules already warned about, keyed "<rule key>@<config hash>". The config
-- hash changes on every save, so an operator who fixes the problem gets a
-- fresh warning, without per-request log spam. The table is reset when the
-- hash changes so it cannot grow without bound across saves.
local _warned = {}
local _warned_hash = nil

local function warn_once(key, ...)
    local hash = config.local_hash or "nohash"
    if hash ~= _warned_hash then
        _warned = {}
        _warned_hash = hash
    end
    if _warned[key] then return end
    _warned[key] = true
    ngx.log(ngx.WARN, ...)
end

-- Is this rule referenced by the kernel-blocking CC policy?
--
-- Only those rules produce CC evidence. The promotion side reads evidence for
-- exactly the rules in cc.rule_ids, so evidence written for any other rule is
-- a dict write nobody reads. This used to be gated on the v2 namespace
-- instead, which meant the evidence chain only ran once the counter namespace
-- had been cut over — and the cutover could not happen without the very
-- kernel-blocking panel that would have consumed the evidence.
--
-- The list is a handful of entries and this is only asked on the first
-- transition past a limit, never per request.
local function cc_referenced(rule_id)
    local kb = config.kernel_ip_blocking
    if not kb or kb.enabled ~= true then return false end
    local cc = kb.cc
    if not cc or cc.enabled == false then return false end
    local ids = cc.rule_ids
    if type(ids) ~= "table" then return false end
    for _, id in ipairs(ids) do
        if id == rule_id then return true end
    end
    return false
end

function _M.on_access(ctx)
    local rules = config.rule and config.rule.frequency_limit
    if not rules then
        return
    end

    local shared = ngx.shared.frequency_limit
    if not shared then
        return
    end

    for idx, rule in ipairs(rules) do
        if rule.enable == false then
            goto continue
        end

        local matcher_def = matcher.resolve(rule)
        if not matcher_def then
            -- A rule with no resolvable matcher matches nothing, forever, and
            -- the failure is otherwise invisible: the panel renders it as a
            -- configured rule and the plugin just skips it. Warn once per rule
            -- per config hash rather than per request — this sits on the
            -- request path, so an unconditional log would flood the error log
            -- on any busy site.
            warn_once("matcher:" .. tostring(rule.id or ("#" .. idx)),
                "frequency_limit: rule '", tostring(rule.id),
                "' has no resolvable matcher and will never match ",
                "(checked matcherJson=", tostring(rule.matcherJson),
                ", matcher=", type(rule.matcher))
            goto continue
        end

        if matcher.test(matcher_def, ctx) then
            local limit = rule.limit or 60
            local window = rule.window or 60
            local enc_dim = limiter.build_key(rule.key or "ip", ctx)
            local key
            if rule.id and rule.id ~= "" then
                key = ip_enc.count_key(ip_enc.encode_rule_id(rule.id), enc_dim)
            else
                -- No stable id: count under a rule-less key and say so once.
                -- Two such rules would share one counter, which is exactly the
                -- collision the per-rule id exists to prevent — the operator
                -- fixes it by saving the rule in the panel, which assigns an
                -- id.
                warn_once("noid:" .. tostring(idx),
                    "frequency_limit: rule #", tostring(idx),
                    " has no stable id; its counter is not isolated from other ",
                    "id-less rules (save the rule in the panel to assign one)")
                key = ip_enc.count_key_noid(enc_dim)
            end
            local current, ierr, iforc = shared:incr(key, 1, 0, window)

            -- Fail CLOSED when the counter could not be recorded at all.
            --
            -- The previous `if current and current > limit` read a nil as "not
            -- counted" and let the request through, so a dict with no room left
            -- would have switched rate limiting off — precisely when something
            -- is deliberately filling it. Treating it as over the limit keeps
            -- the control working, and turns a silent hole into visible 429s.
            if current == nil then
                dict_guard.write_failed("frequency_limit.count", "incr", ierr)
                ctx.set_data(ctx, "frequency_limit:counter_unrecorded", true)
                current = limit + 1
            elseif iforc then
                -- The counter WAS written, so limiting is working and must not
                -- be turned into a block here. But it only fitted because some
                -- other key was evicted by LRU, which outranks expiry: another
                -- subject's counter is now gone and they will appear to have
                -- made no requests at all. lua_shared_dict has no noevict
                -- policy argument, so this cannot be prevented — it can only
                -- be reported.
                dict_guard.evicted_other("frequency_limit.count", "incr")
                ctx.set_data(ctx, "frequency_limit:counter_forced", true)
            end

            if current > limit then
                -- Record CC violation evidence on FIRST transition past limit
                -- (current == limit + 1 means this request just crossed the threshold)
                if current == limit + 1 and rule.id and rule.id ~= ""
                    and cc_referenced(rule.id) then
                    local ip = ip_enc.canonical_ip(ctx.request.remote_addr)
                    ev.record_cc_violation_evidence(rule.id, ip, window)
                end

                ctx.set_data(ctx, "frequency_limit:limited", true)
                -- `response` must name a template registered under
                -- config.response — action/response.lua looks the string up
                -- there and serves "response template not found" when it
                -- misses. The old default was the human phrase "Too Many
                -- Requests", so every block-action frequency rule answered
                -- with that internal error string as its body (HTTP 429 with
                -- body "response template not found"). Point at the shipped
                -- template instead, which carries the Retry-After header.
                -- The type/emptiness guard matters because "" is truthy in
                -- Lua: `rule.response or default` would let a blank value
                -- through to the lookup and fail there.
                local resp_name = rule.response
                if type(resp_name) ~= "string" or resp_name == "" then
                    resp_name = "too_many_requests"
                end
                ctx.set_action(ctx, "block", {
                    code = rule.code or 429,
                    response = resp_name
                })
                return
            end
        end
        ::continue::
    end
end

return _M
