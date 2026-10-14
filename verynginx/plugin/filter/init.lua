local _M = {}

_M.name = "filter"
_M.priority = 100
_M.default_enable = true
_M.critical = true

local config = require "core.config"
local matcher = require "matcher.init"
local waf_manager = require "waf-rule-manager"
local ip_reputation = require "core.ip_reputation"
local crawler_verify = require "core.crawler_verify"
local tls_fingerprint = require "core.tls_fingerprint"
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
        -- WAF rules never pass through the config-compile path, so
        -- pre-compute their matcher hot-path data (CRC + sorted conditions,
        -- recursing into Composite) here, once per rule load — otherwise
        -- every request re-does json.encode + crc32 + sort per definition.
        local rule_md = matcher.resolve(rule)
        if rule_md then matcher.precompute(rule_md) end
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
        local pa, pb = a.priority or 100, b.priority or 100
        if pa ~= pb then return pa < pb end
        -- Deterministic tie-break: Lua's table.sort is unstable, so without
        -- it same-priority rules evaluate in arbitrary order — and which
        -- block rule records the hit (first match returns) became luck.
        return (a.id or "") < (b.id or "")
    end)
    table.sort(challenge, function(a, b)
        local pa, pb = a.priority or 100, b.priority or 100
        if pa ~= pb then return pa < pb end
        return (a.id or "") < (b.id or "")
    end)
    return hard_block, challenge
end
_M._split_rules = split_rules -- exported for unit tests (tie-break order)

-- Synthetic rule id for requests the scanner could not inspect (body over
-- body.max_size, args over max_args, parse failures). Previously each Args
-- condition fail-closed to "match", so whichever Args rule sorted first
-- claimed the hit — usually vn_sqli_0001 — mislabelling large legitimate
-- uploads as SQL injection and, on default installs (factory action=block),
-- 403ing them. One honest synthetic hit replaces that masquerade.
local UNINSPECTABLE_ID = "vn_body_uninspectable"

--- Record a single honest hit for a request whose body/args could not be
-- (fully) inspected, and honour body.on_error. on_error was previously read
-- only to decide whether to LOG the hit, so the advertised "fail_closed"
-- never blocked. Semantics now:
--   fail_closed -> block the request, attributed to vn_body_uninspectable
--                  (NOT a mislabelled sqli/xss rule); mirrors evaluate_rules'
--                  block branch so reputation/kernel-blocking see a normal
--                  block. Applies ONLY to suspicious causes (args overflow,
--                  parse failure) — never to a large body.
--   skip        -> pass silently, no hit.
--   log/match/unset -> record one synthetic hit and pass (observe; default).
-- LARGE-BODY causes (body_too_large / body_truncated — the ProcessPartial
-- prefix was scanned, only the unaffordable tail was skipped) are always
-- observe-only: a >max_size body is legitimate traffic (uploads, imports) and
-- must never be 403'd merely for being large. Per-rule opt-in stays available
-- via each Args condition's on_body_error.
-- Returns true when a hit was recorded (block or observe), false otherwise.
local BODY_SIZE_ERR = { body_too_large = true, body_truncated = true }
function _M._record_uninspectable(ctx)
    local err = ctx.request and (ctx.request._body_error
        or ctx.request._uri_args_error)
    if not err then return false end
    local policy = (config and config.body and config.body.on_error) or "log"
    if policy == "skip" then return false end

    local ip = ctx.request.remote_addr
    local blockable = not BODY_SIZE_ERR[err]
    if policy == "fail_closed" and blockable then
        waf_manager.record_hit(UNINSPECTABLE_ID, ctx, "block")
        -- Only set the decision / fire signals when no rule already decided
        -- this request (avoid double-counting a block a rule already made).
        local already = ctx.has_decision and ctx.has_decision(ctx)
        if not already then
            ip_reputation.record_signal(ip, "waf_block")
            if config.kernel_ip_blocking and config.kernel_ip_blocking.enabled then
                pcall(function()
                    local kb = require "core.kernel_blocking.evidence"
                    kb.record_waf_block_evidence(ip)
                end)
            end
            ctx.set_action(ctx, "block", { code = 403, response = "forbidden_json" })
        end
        ngx.log(ngx.WARN, "waf: uninspectable request (", tostring(err),
            ") blocked by body.on_error=fail_closed")
        return true
    end
    -- observe: large body under any policy, or log/match/default for other
    -- causes. One honest synthetic hit; the request passes.
    waf_manager.record_hit(UNINSPECTABLE_ID, ctx, "log")
    ngx.log(ngx.WARN, "waf: request not fully inspectable (", tostring(err),
        ") — recorded synthetic hit ", UNINSPECTABLE_ID)
    return true
end
_M.UNINSPECTABLE_ID = UNINSPECTABLE_ID

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

        -- Verified-crawler exemption. Checked BEFORE the hit is recorded so a
        -- skipped rule leaves no trace in the rule statistics either — a
        -- crawler that is let through should not look like a rule that
        -- matched, and the panel's per-rule hit counts stay meaningful.
        --
        -- Two independent routes to "let it through":
        --   1. the source IP is inside a range the vendor publishes
        --   2. the User-Agent claims a vendor we verify by DNS, and that
        --      check has not yet condemned it
        -- Route 2's verdict is decided OFF the request path (a timer), so
        -- the first contact is always allowed and the result lands in the
        -- cache for everyone after it. That ordering is deliberate: a DNS
        -- outage must never start blocking a real crawler, and a first
        -- request costing a scraper one page is not worth a wrong 403.
        --
        -- Attack categories are exempt from neither route: a crawler
        -- fetching a URL carrying an injection is still an injection.
        local exempt = ip_reputation.is_crawler_exempt(rule, ip)
        if not exempt and crawler_verify.is_enabled() then
            local claimed = crawler_verify.claimed_vendor(ctx.request.user_agent)
            if claimed then
                local verdict = crawler_verify.verdict(ip)
                if verdict ~= crawler_verify.VERDICT_FAKE then
                    -- verified, or not yet decided: let it through and make
                    -- sure a verdict is on its way.
                    if not verdict then
                        crawler_verify.schedule(ip, claimed)
                    end
                    exempt = true
                end
                -- verdict == fake: fall through to the normal block path.
            end
        end
        if exempt then
            goto continue
        end

        waf_manager.record_hit(rule.id, ctx, action)

        if action == "accept" then
            ip_reputation.clear_pending(ip)
            ctx.set_action(ctx, "accept")
            return true
        elseif action == "block" then
            ip_reputation.record_signal(ip, "waf_block", rule)
            if config.kernel_ip_blocking and config.kernel_ip_blocking.enabled then
                if not evidence then evidence = require "core.kernel_blocking.evidence" end
                evidence.record_waf_block_evidence(ip)
            end
            ctx.set_action(ctx, "block", { code = rule.code or 403, response = rule.response })
            return true
        elseif action == "challenge" then
            ip_reputation.record_signal(ip, "waf_challenge", rule)
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
    -- ctx.request.ja3_fingerprint used to be READ here but never WRITTEN by
    -- anyone (the only producer ran later, inside hit-detail building), so
    -- this whole block was dead code. The fingerprint now comes from
    -- core.tls_fingerprint, which computes JA4 once per handshake (or falls
    -- back to the legacy JA3 module / negotiated-cipher string) and caches the
    -- record per request. We publish it on ctx.request under the historical
    -- key so hit details and alerting keep reading one identical value.
    if not fingerprint_db then fingerprint_db = require "core.fingerprint_db" end
    if ctx.request.ja3_fingerprint == nil then
        local rec = tls_fingerprint.get()
        if rec then
            ctx.request.ja3_fingerprint = rec.value
            ctx.request.tls_fingerprint = rec
        end
    end
    local ja3 = ctx.request.ja3_fingerprint
    if ja3 then
        local match = fingerprint_db.match(ctx.request.tls_fingerprint or ja3)
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

    -- 【阶段一后】无法检测请求的诚实归因：Args 条件的懒读已在上面触发，
    -- 若 body/args 解析失败或超限，按 body.on_error 处理——fail_closed 阻断
    -- 该请求（诚实归因到 vn_body_uninspectable），否则记录一条合成命中（P1-4）。
    _M._record_uninspectable(ctx)
    if decided or (ctx.has_decision and ctx.has_decision(ctx)) then
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
