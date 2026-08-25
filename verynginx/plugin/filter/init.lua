local _M = {}

_M.name = "filter"
_M.priority = 100
_M.default_enable = true
_M.critical = true

local config = require "core.config"
local matcher = require "matcher.init"
local waf_manager = require "waf-rule-manager"
local ip_reputation = require "core.ip_reputation"
local javascript_verify = require "plugin.browser_verify.javascript_verify"
local metrics = require "core.metrics"
local geoip = nil -- lazy loaded in on_access()
local fingerprint_db = nil -- lazy loaded in on_access()
local evidence = nil -- lazy loaded (kernel blocking evidence)

-- Rule cache: avoids JSON-decoding all chunks on every request
local _rule_cache = { version = nil, hard_block = nil, challenge = nil }

local function split_rules(all_rules)
    local hard_block, challenge = {}, {}
    for _, rule in ipairs(all_rules) do
        if not rule.enable then goto continue end
        local action = rule.action or "log"
        if action == "block" or action == "accept" then
            table.insert(hard_block, rule)
        elseif action == "challenge" then
            table.insert(challenge, rule)
        elseif action == "log" then
            table.insert(hard_block, rule)
        end
        ::continue::
    end
    table.sort(hard_block, function(a, b)
        return (a.priority or 100) < (b.priority or 100)
    end)
    table.sort(challenge, function(a, b)
        return (a.priority or 100) < (b.priority or 100)
    end)
    return hard_block, challenge
end

local function evaluate_rules(rules, ctx, ip)
    for _, rule in ipairs(rules) do
        if rule.enable == false then goto continue end

        local matcher_def = matcher.resolve(rule)
        if not matcher_def then goto continue end

        local matched = matcher.test(matcher_def, ctx)
        if not matched then goto continue end

        if not waf_manager.check_rate_limit(rule.id, rule) then
            goto continue
        end

        local action = rule.action or "log"

        waf_manager.record_hit(rule.id, ctx, action)

        if action == "accept" then
            ip_reputation.clear_pending(ip)
            ctx.set_action(ctx, "accept")
            return true
        elseif action == "block" then
            ip_reputation.record_signal(ip, "waf_block")
            if config.kernel_ip_blocking and config.kernel_ip_blocking.enabled then
                if not evidence then evidence = require "core.kernel_blocking.evidence" end
                evidence.record_waf_block_evidence(ip)
            end
            ctx.set_action(ctx, "block", { code = rule.code or 403, response = rule.response })
            return true
        elseif action == "challenge" then
            ip_reputation.record_signal(ip, "waf_challenge")
            if ngx.ctx.is_flagged then
                ctx.set_action(ctx, "block", { code = 403, response = rule.response })
                return true
            end
            ip_reputation.set_pending(ip)
            -- Track which rule triggered the challenge (set-like, avoids string concat)
            local pending_key = "ip_rep:pending_rules:" .. ip .. ":" .. rule.id
            ngx.shared.ip_reputation:add(pending_key, "1", 600)
            -- Increment challenge served counter
            metrics.incr("ip_reputation_challenge_served_total", 1, {})
            ctx.set_action(ctx, "challenge", {
                javascript_verify = javascript_verify
            })
            ctx.set_data(ctx, "reputation:challenge_response", true)
            return true
        elseif action == "log" then
            ngx.log(ngx.WARN, "waf: rule matched [", rule.id, "] ", rule.name)
        end

        ::continue::
    end
    return false
end

local function get_cached_rules()
    local shared = ngx.shared.vn_config
    if not shared then
        local rules_obj = waf_manager.load_rules()
        if not rules_obj then return nil, nil end
        return split_rules(rules_obj.rules)
    end
    -- Lightweight version fast-path: read the *committed* version key
    -- (waf_rules_version), which save_rules only sets AFTER the chunked cache
    -- and meta are fully written. Checking the pre-incremented
    -- waf_rules_save_version (bumped at the START of a save) would let a
    -- worker reload the still-old chunks and cache them under the new version,
    -- leaving a stale rule set cached until the next save.
    local version_raw = shared:get("waf_rules_version")
    if version_raw and tonumber(version_raw) == _rule_cache.version then
        return _rule_cache.hard_block, _rule_cache.challenge
    end
    local rules_obj = waf_manager.load_rules()
    if not rules_obj or not rules_obj.rules or #rules_obj.rules == 0 then
        local fallback = require "plugin.filter.rules"
        local fb = fallback.load_rules()
        if not fb or #fb == 0 then return nil, nil end
        local h, c = split_rules(fb)
        _rule_cache.version = version_raw and tonumber(version_raw) or 0
        _rule_cache.hard_block, _rule_cache.challenge = h, c
        return h, c
    end
    local h, c = split_rules(rules_obj.rules)
    _rule_cache.version = version_raw and tonumber(version_raw) or 0
    _rule_cache.hard_block, _rule_cache.challenge = h, c
    return h, c
end

function _M.on_access(ctx)
    local ip = ctx.request.remote_addr

    -- 【前置-1】管理路径放行 (exact or "/"-bounded suffix; see api/init.lua)
    local base_uri = (config and config.base_uri) or "/verynginx"
    local uri0 = ctx.request.uri
    if uri0 == base_uri or (uri0:find(base_uri, 1, true) == 1 and uri0:sub(#base_uri + 1, #base_uri + 1) == "/") then
        return
    end

    -- 【前置-0】请求计数 + UA 采集
    ip_reputation.increment_req(ip)
    ip_reputation.record_ua(ip, ctx.request.user_agent or "")

    -- 【前置-1.5】静态 IP 白名单 → 直接放行
    if ip_reputation.is_whitelisted(ip) then
        return
    end

    -- 【前置-1.6】GeoIP 检查（如果在数据库中）
    if not geoip then geoip = require "core.geoip" end
    if geoip.is_available() then
        local geo = geoip.cached_lookup(ip)  -- single FFI call, cached in ngx.ctx
        local blocked = geoip.check_block(ip, geo)
        if blocked then
            ip_reputation.record_signal(ip, "geoip_block")
            ctx.set_action(ctx, "block", { code = 403, response = "forbidden_json" })
            return
        end
        -- Track country for stats (reuses cached geo data)
        geoip.track(ip, ngx.shared.vn_config, geo)
    end

    -- 【前置-1.7】TLS 指纹检查
    if not fingerprint_db then fingerprint_db = require "core.fingerprint_db" end
    local ja3 = ctx.request.ja3_fingerprint
    if ja3 then
        local match = fingerprint_db.match(ja3)
        if match then
            if match.action == "block" and (config.fingerprints.auto_block_scanners ~= false) then
                ip_reputation.record_signal(ip, "fingerprint_block")
                ctx.set_action(ctx, "block", { code = 403, response = "forbidden_json" })
                return
            elseif match.action == "challenge" then
                ip_reputation.record_signal(ip, "fingerprint_challenge")
            end
            ctx.set_data(ctx, "fingerprint:match", match)
        end
    end

    -- 【前置-3】IP 已被标记为扫描器 → 直接封禁
    ngx.ctx.is_flagged = ip_reputation.is_flagged(ip)
    if ngx.ctx.is_flagged then
        ctx.set_action(ctx, "block", { code = 403, response = "forbidden_json" })
        return
    end

    -- 加载规则并按类型分组（带版本号缓存）
    local hard_block_rules, challenge_rules = get_cached_rules()
    if not hard_block_rules then
        return
    end

    -- 【阶段一】始终执行硬 block 规则
    local decided = evaluate_rules(hard_block_rules, ctx, ip)
    if decided then
        return
    end

    -- 【前置-2】检查 JS 验证 cookie
    -- 仅跳过 challenge 类规则，硬 block 规则已在阶段一处理完毕
    local cookie_verified = javascript_verify.check(ctx)
    if cookie_verified then
        ip_reputation.clear_score(ip)
        ip_reputation.record_challenge_pass(ip)
        -- Record challenge pass for rules that issued this challenge
        local ctx_ip = ctx.request.remote_addr
        local s = ngx.shared.vn_config
        for _, r in ipairs(challenge_rules) do
            local pk = "ip_rep:pending_rules:" .. ctx_ip .. ":" .. r.id
            if ngx.shared.ip_reputation:get(pk) then
                -- Per-DAY key: the analytics pass-rate divides this by the
                -- per-day challenge counter — both must share a window or
                -- the rate drifts toward zero as lifetime totals grow.
                local pday = os.date("!%Y%m%d")
                s:incr("waf_rule_stats:" .. tostring(r.id) .. ":cpass:" .. pday, 1, 0, 172800)
                ngx.shared.ip_reputation:delete(pk)
            end
        end
        ctx.set_data(ctx, "reputation:challenge_passed", true)
        return
    end

    -- 【检查 pending 状态】仅当无有效 cookie 时才有意义
    if ip_reputation.has_pending(ip) then
        ip_reputation.record_signal(ip, "challenge_fail")
        ip_reputation.clear_pending(ip)
        if config.kernel_ip_blocking and config.kernel_ip_blocking.enabled then
            pcall(function()
                local kb_evidence = require "core.kernel_blocking.evidence"
                kb_evidence.record_challenge_fail_evidence(ip)
            end)
        end
    end

    -- 【阶段二】无有效 cookie 时，执行 challenge 类规则
    evaluate_rules(challenge_rules, ctx, ip)
end

return _M
