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
local geoip = nil -- lazy loaded in on_access()
local fingerprint_db = nil -- lazy loaded in on_access()

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
            ctx.set_action(ctx, "block", { code = rule.code or 403, response = rule.response })
            return true
        elseif action == "challenge" then
            ip_reputation.record_signal(ip, "waf_challenge")
            if ip_reputation.is_flagged(ip, { no_cache = true }) then
                ctx.set_action(ctx, "block", { code = 403, response = rule.response })
                return true
            end
            ip_reputation.set_pending(ip)
            -- Track which rule triggered the challenge for pass-rate analytics
            local pending_rules = ngx.shared.ip_reputation:get("ip_rep:pending_rules:" .. ip) or ""
            if not pending_rules:find(rule.id, 1, true) then
                pending_rules = pending_rules ~= "" and (pending_rules .. "," .. rule.id) or rule.id
                ngx.shared.ip_reputation:set("ip_rep:pending_rules:" .. ip, pending_rules, 600)
            end
            -- Increment challenge served counter
            local metrics = require "core.metrics"
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

function _M.on_access(ctx)
    local ip = ctx.request.remote_addr

    -- 【前置-1】管理路径放行
    local base_uri = (config and config.base_uri) or "/verynginx"
    if ctx.request.uri:find(base_uri, 1, true) == 1 then
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
        local blocked = geoip.check_block(ip)
        if blocked then
            ip_reputation.record_signal(ip, "geoip_block")
            ctx.set_action(ctx, "block", { code = 403, response = "forbidden_json" })
            return
        end
        -- Track country for stats
        geoip.track(ip, ngx.shared.vn_config)
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
    if ip_reputation.is_flagged(ip) then
        ctx.set_action(ctx, "block", { code = 403, response = "forbidden_json" })
        return
    end

    -- 加载规则并按类型分组
    local rules_obj = waf_manager.load_rules()
    local all_rules
    if rules_obj and rules_obj.rules and #rules_obj.rules > 0 then
        all_rules = rules_obj.rules
    else
        local fallback = require "plugin.filter.rules"
        all_rules = fallback.load_rules()
    end
    if not all_rules or #all_rules == 0 then
        return
    end
    local hard_block_rules, challenge_rules = split_rules(all_rules)

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
        local pending_rules = ngx.shared.ip_reputation:get("ip_rep:pending_rules:" .. ctx_ip)
        if pending_rules and pending_rules ~= "" then
            local s = ngx.shared.vn_config
            for rule_id in pending_rules:gmatch("[^,]+") do
                local pass_key = "waf_rule_challenge_pass:" .. rule_id
                s:incr(pass_key, 1, 0, 86400)
            end
            ngx.shared.ip_reputation:delete("ip_rep:pending_rules:" .. ctx_ip)
        end
        ctx.set_data(ctx, "reputation:challenge_passed", true)
        return
    end

    -- 【检查 pending 状态】仅当无有效 cookie 时才有意义
    if ip_reputation.has_pending(ip) then
        ip_reputation.record_signal(ip, "challenge_fail")
        ip_reputation.clear_pending(ip)
    end

    -- 【阶段二】无有效 cookie 时，执行 challenge 类规则
    evaluate_rules(challenge_rules, ctx, ip)
end

return _M
