# IP 声誉评分引擎 + Challenge 机制设计方案

> **目标**：区分正常用户访问与自动化扫描器，在保持安全性的同时减少对正常用户（如 phpMyAdmin 管理员）的误杀。

---

## 一、整体思路

- **方案 A（IP 声誉评分引擎）** — 解决"谁来判定是否扫描器"
- **方案 B（Challenge 替代 Block）** — 解决"判定后怎么处理"

两者协作的核心逻辑：

```
每次请求进入 filter 插件
  ├─ 【前置-1】管理路径检查 → 匹配则放行
  ├─ 【前置-0】请求计数 ip_rep:req++
  ├─ 【前置-1.5】静态白名单检查 → 匹配则放行
  ├─ 【前置-3】IP 已被标记为扫描器（冷却期）？ → 直接 block (403)
  ├─ 【阶段一】硬 block 规则 （SQLi/RCE/path traversal/scanner UA）
  │    ├─ 命中 block 规则 → 记录 waf_block (+5) + set_action("block")
  │    │   └─ TERMINAL_ACTIONS 包含 block → 插件链中断
  │    └─ 命中 accept 规则 → set_action("accept")
  ├─ 【检查 pending 状态】→ challenge_fail (+5) 如果 pending 超时
  ├─ 【前置-2】JS cookie 验证
  │    ├─ cookie 有效 → clear_score(ip)，return 放行（仅跳过 challenge 规则）
  │    └─ 无 cookie → 继续阶段二
  ├─ 【阶段二】challenge 规则（仅在无有效 cookie 时执行）
  │    └─ 命中 challenge 规则 → set_action("challenge") + set_pending(ip)
  │        └─ TERMINAL_ACTIONS 包含 challenge → 插件链中断
  └─ 实时计算总分 → 超过阈值 → 标记为扫描器，进入冷却期
```

> **⚠️ 安全约束（任何实现不得违反）：**
> - 硬 block 规则（SQLi/RCE/path traversal）在 cookie 检查**之前**执行
> - cookie 验证通过只跳过 challenge 类规则，**不得**跳过硬 block 规则
> - 规则执行顺序：阶段一（block/accept）→ cookie 检查 → 阶段二（challenge）
> - 违反此约束将导致 WAF bypass：攻击者获取 cookie 后直接发送 SQLi/RCE payload

### phpMyAdmin 正常访问流程

用户第一次命中扫描类规则 → 收到 JS challenge → 浏览器自动执行 JS 通过 → 获得验证 cookie → **后续请求检查 cookie 直接放行**，不再触发 challenge。

扫描器则无法通过 JS，反复 challenge 失败后声誉分数飙升，被直接封禁。

---

## 二、方案 A：IP 声誉评分引擎

### 2.1 模块位置

新建 `core/ip_reputation.lua`

### 2.2 共享字典

需在 `nginx_conf/in_http_block.conf` 中新增：

```nginx
lua_shared_dict ip_reputation 16m;
```

> **注意**：从原方案 5m 提升到 16m。高并发场景下活跃 IP 数可达数万，每个 IP 在 5 个时间槽中存储多种信号，5m 不足。详见附录中的内存估算。

### 2.3 数据结构（时间分槽计数器）

采用时间分槽计数器实现滑动窗口，这是 nginx/lua 生态的标准做法：

- 窗口 300s，槽 60s，共 5 个槽

| Key 格式 | 含义 | TTL |
|----------|------|-----|
| `ip_rep:waf:<ip>:<slot>` | 该槽内 WAF 规则累计分值（record_signal 按权重递增：waf_challenge +3, waf_block +5） | 300s |
| `ip_rep:404:<ip>:<slot>` | 该槽内 404 响应次数 | 300s |
| `ip_rep:req:<ip>:<slot>` | 该槽内总请求数 | 300s |
| `ip_rep:challenge_fail:<ip>:<slot>` | 该槽内 challenge 失败累计分值（每次 +5） | 300s |
| `ip_rep:flagged:<ip>` | 标记时间戳，存在则表示冷却中；自动检测路径在 score≥threshold 时调用 flag_ip() 写入 | = 冷却时长 |
| `ip_rep:flagged_today` | 当日已标记 IP 总数（自动递增，用于 get_stats 面板统计） | 86400s |
| `ip_rep:pending:<ip>` | challenge 已发出的时间戳，不存在表示无待验证 | 300s |
| `ip_rep:ua_count:<ip>:<slot>` | 该槽内不同 UA 的近似计数（通过 `shared:add` 原子性增量维护） | 300s |
| `ip_rep:ua_seen:<ip>:<slot>:<hash>` | UA hash 存在性标记（`shared:add` 仅首次成功，用于去重） | 300s |
| `ip_rep:cache:<ip>` | is_flagged 结果缓存（10s 有效期，避免高频遍历） | 10s |
| `ip_rep:flagged_index` | JSON array：当前已标记 IP 列表（避免 get_keys 全量扫描） | 无 TTL（手动维护） |

> **关键变更**：
> - **record_signal 语义**：shared dict 键存储的是**累计分值**而非原始命中次数。`record_signal(ip, "waf_challenge", uri)` 内部通过 `shared:incr(key, 3, 0, 300)` 递增 3 分，`waf_block` 递增 5 分，`challenge_fail` 递增 5 分，`not_found` 递增 1 分。`get_score()` 直接对所有槽的数值求和 × diversity_factor，无需区分信号类型。
> - 删除 `ip_rep:score:<ip>` — score 是实时计算的，不需要单独存储
> - 新增 `ip_rep:pending:<ip>` — 替代设计方案中"log 阶段检测失败"的不可行方案
> - `slot` = `math.floor(ngx.time() / slot_size)`

### 2.4 评分规则

| 信号 | 分值 | 触发点 |
|------|------|--------|
| WAF challenge 规则命中 | +3 | filter 插件命中 challenge 规则时 |
| WAF block 规则命中 | +5 | filter 插件命中 block 规则时 |
| 404 响应 | +1 | summary 插件 log 阶段统计 |
| Challenge 失败（cookie 未回传） | +5 | filter 插件检测到 pending 仍无有效 cookie |

**衰减机制**：每个时间槽 (60s) 自动过期，效果等同于"旧信号权重递减"。无需主动衰减操作。

**评分频率加权**（防共享 IP 误伤）：
```
final_score = raw_score * diversity_factor
diversity_factor = max(0.5, 1.0 - (distinct_ua_count - 1) * 0.1)
```
同一 IP 出现 3 种以上不同 UA（通过 `ip_rep:ua_count:<ip>:<slot>` 近似计数跟踪），判定为共享 NAT，评分权重适当打折。例如 distinct_ua_count = 3 → factor = 0.8；distinct_ua_count = 6 → factor = 0.5（评分权重减半）。

> **min_requests 判定**：`is_flagged()` 内部先计算 `ip_rep:req` 的滑动窗口总请求数，若 < `min_requests`（默认 3），直接返回 `false`，跳过评分。避免偶发访问被误判。min_requests=3 配合评分周期：首次 challenge waf_challenge +3，之后每轮循环（challenge_fail +5 + waf_challenge +3）累计 +8。在请求 4 时分数达到 3 + (5+3) + (5+3) + (5+3) = 27，超过阈值 25。因此扫描器通常 4 次请求内触发标记。

### 2.5 阈值与冷却

```lua
default_config = {
    enable = true,
    threshold = 25,          -- 分数达到此值 → 标记为扫描器（从 20 提高到 25，降低误杀）
    flag_duration = 600,     -- 冷却时长 10 分钟
    window_size = 300,       -- 滑动窗口 5 分钟
    slot_size = 60,          -- 槽粒度 60 秒
    min_requests = 3,        -- 窗口内最少请求数才参与评分（3 次足以区分扫描器和偶发访问）
    pending_ttl = 600,       -- challenge pending 有效期 10 分钟（与 cookie Max-Age 对齐）
    whitelist = {            -- 静态 IP 白名单（不受 challenge 影响）
        -- "127.0.0.1",
        -- "10.0.0.0/8",
    },
}
```

### 2.6 核心 API

```lua
-- ========== 内部采集 API（从 filter/summary 插件调用） ==========

-- 记录信号（从 filter 插件和 summary 插件调用）
ip_reputation.record_signal(ip, signal_type, uri)

-- 请求计数（每次请求调用，用于 min_requests 判定）
ip_reputation.increment_req(ip)

-- 更新 UA 近似计数（每次请求调用）
-- 实现：
--   local slot = math.floor(ngx.time() / 60)
--   local hash = ngx.crc32_short(ua_string)
--   local shared = ngx.shared.ip_reputation
--   local seen_key = "ip_rep:ua_seen:" .. ip .. ":" .. slot .. ":" .. hash
--   local is_new = shared:add(seen_key, 1, 300)  -- 原子性：仅首次成功
--   if is_new then
--       shared:incr("ip_rep:ua_count:" .. ip .. ":" .. slot, 1, 0, 300)
--   end
-- distinct_ua_count 近似 = 窗口内 ip_rep:ua_count:<ip>:<slot> 各槽求和
ip_reputation.record_ua(ip, ua_string)

-- ========== 查询/判定 API（从 filter 插件调用） ==========

-- 查询 IP 是否在冷却期
--   opts.no_cache = true 时跳过 10s 结果缓存（用于本次请求刚 record_signal 后的实时判定）
--   内部逻辑：
--     1. 先检查 ip_rep:flagged:<ip> 是否存在且未过期 → 存在则直接返回 true
--     2. 检查 min_requests 门槛（窗口内请求数 < min_requests → 返回 false，跳过评分）
--     3. 计算 score × diversity_factor（get_score 已含 diversity_factor）
--     4. 若 score ≥ threshold → 自动调用 flag_ip 写入冷却期 + flagged_index，返回 true
-- 缓存策略：默认结果缓存 10 秒（ip_rep:cache:<ip>），避免高频请求重复遍历
ip_reputation.is_flagged(ip, opts) → boolean

-- 获取当前分数（实时计算：遍历窗口内所有槽求和 × diversity_factor）
ip_reputation.get_score(ip) → number

-- 标记/清除 challenge pending 状态
ip_reputation.set_pending(ip)
ip_reputation.has_pending(ip) → boolean
ip_reputation.clear_pending(ip)

-- ========== 手动操作 API（Dashboard 调用） ==========

ip_reputation.flag_ip(ip, duration)        -- 手动标记（duration 秒冷却期）
ip_reputation.clear_ip(ip)                 -- 手动清除（提前解除冷却期）
ip_reputation.clear_score(ip)             -- 清零分数（但不解除冷却期）
ip_reputation.add_whitelist(ip)           -- 加入永久白名单
ip_reputation.remove_whitelist(ip)        -- 移出白名单
ip_reputation.is_whitelisted(ip) → boolean -- 检查是否在白名单

-- ========== 持久化/查询 API（Dashboard/定时器调用） ==========

ip_reputation.list_flagged() → table      -- 已标记 IP 列表
ip_reputation.list_whitelist() → table    -- 白名单列表
ip_reputation.get_stats() → table         -- 全局统计：flagged 数、pending 数、今日封禁数
ip_reputation.persist()                   -- 触发持久化
ip_reputation.restore()                   -- 从磁盘恢复
```

### 2.7 信号采集点

| 采集点 | 阶段 | 采集内容 |
|--------|------|----------|
| `plugin/filter/init.lua` | access 阶段 | challenge 规则命中时调用 `record_signal(ip, "waf_challenge")`，并调用 `set_pending(ip)` |
| `plugin/filter/init.lua` | access 阶段 | block 规则命中时调用 `record_signal(ip, "waf_block")` |
| `plugin/filter/init.lua` | access 阶段 | 检测 pending + 无 cookie 时调用 `record_signal(ip, "challenge_fail")` |
| `plugin/summary/init.lua` | log 阶段 | `tonumber(ngx.var.status) == 404` 时调用 `record_signal(ip, "not_found", uri)`（无有效 challenge cookie 才计数）；challenge 响应标记时排除 statistics 统计 |
| `plugin/browser_verify/javascript_verify.lua` | challenge 阶段 | cookie 由 challenge HTML 的 JS 设置，Max-Age=600s；签名不含时间分量，保持当前 sign() 不变 |

---

## 三、方案 B：Challenge 动作实现

### 3.1 现状分析

现有架构中的两个关键机制会影响 challenge 动作的设计：

**机制 A — `core/plugin.lua` 的 pcall 包裹（不构成正确性问题）**
- `execute_access` 用 `pcall` 包裹每个插件的 `on_access`
- 在 OpenResty 中，lua-nginx-module 重写了协程退出路径，`ngx.exit`/`ngx.redirect` 抛出的内部异常**不会被** `pcall` 吞没
- 因此现有插件（如 browser_verify）在 pcall 内调用 ngx.exit 是安全的
- **设计决策**：尽管如此，challenge 仍然通过 `set_action → rule_engine.apply()` 路径统一执行，与其他 terminal action 保持一致的架构
- 这不是为了修复 bug，而是为了代码统一性

**机制 B — `core/plugin.lua` 的 TERMINAL_ACTIONS**
```lua
local TERMINAL_ACTIONS = { block = true, redirect = true, response = true }
```
- `execute_access` 在每次循环迭代时检查：`if ctx.has_decision(ctx) and _M._is_terminal(ctx) then break end`
- **不在 TERMINAL_ACTIONS 中的 action 不会中断插件链**
- 目前 challenge 不在表中，设置后插件链继续执行
- 后果：filter 设置 challenge 后，frequency_limit(200)→browser_verify(300)→router(400)→proxy_pass(500) 继续执行，proxy_pass 可能覆盖 challenge 动作

**机制 C — `core/rule_engine.lua` 的 action apply**
- `rule_engine.apply()` 负责把 action 落地为 Nginx 响应（ngx.exit/ngx.redirect 等）
- 当前 RESULT 表没有 CHALLENCH，apply() 无对应分支
- 即使 action 未被覆盖，也没有代码负责输出 challenge HTML

**机制 D — JS Cookie 验证不能跳过硬 block 规则（security regression 警告）**
- 如果在 cookie 检查后直接 `return`（前置-2），会跳过所有 block 规则
- 攻击者使用真实浏览器（Puppeteer/Playwright）可以轻松执行 JS challenge 获取 cookie
- 获取 cookie 后所有请求跳过 WAF → SQLi/RCE payload 直接打到后端
- **正确做法**：规则分为两组，硬 block 规则 SQLi/RCE/path traversal 始终执行，仅 challenge 类规则可以跳过
- 对应实现：`split_rules()` 分组 + `evaluate_rules()` 分两阶段执行

### 3.2 改动点

#### 3.2.1 `plugin/filter/init.lua` — 完整改动

**⚠️ 设计决策 — challenge 通过 rule_engine.apply() 统一执行（保持一致的终止路径）**

OpenResty 的 lua-nginx-module 重写了 `pcall`/`xpcall`，使得 `ngx.exit`/`ngx.redirect` 抛出的内部异常**不会**被 `pcall` 捕获——异常在插件内部仍然可以终止请求。因此 browser_verify 插件的 `challenge() → ngx.exit(200)` 在 pcall 内也能正常工作，现有代码没有正确性问题。

> **注意**：第一次审查此方案时我们误判了 pcall 行为（错误认为 ngx.exit 会被 pcall 吞没）。实际上 OpenResty 重写了协程退出路径，确保 exit 异常透传。

**尽管如此**，filter 的 challenge 动作仍然采用 `set_action` + `rule_engine.apply()` 的模式，与其他 terminal action（block/redirect/response）保持一致。这不是因为 pcall 问题，而是为了**统一的架构一致性**：
- 所有终止动作都通过 `rule_engine.apply()` 落地（一个入口点）
- filter 插件不直接操作响应，降低插件耦合
- 便于日志、指标和调试的统一采集

因此最终方案不变，但不再以 pcall 问题作为动机，而是基于架构一致性设计。

```lua
local ip_reputation = require "core.ip_reputation"
local javascript_verify = require "plugin.browser_verify.javascript_verify"
local waf_manager = require "waf-rule-manager"

--- 将规则分为两组：hard_block 始终执行，challenge_rules 仅在无有效 cookie 时执行
local function split_rules(all_rules)
    local hard_block, challenge = {}, {}
    for _, rule in ipairs(all_rules) do
        if not rule.enable then goto continue end
        local action = rule.action or "log"
        if action == "block" or action == "accept" then
            table.insert(hard_block, rule)      -- 始终执行
        elseif action == "challenge" then
            table.insert(challenge, rule)      -- 可被 cookie 跳过
        elseif action == "log" then
            table.insert(hard_block, rule)      -- log 也始终执行
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

--- 规则匹配分发的核心函数
local function evaluate_rules(rules, ctx, ip, waf_manager)
    for _, rule in ipairs(rules) do
        if rule.enable == false then goto continue end

        local matcher_def = matcher.resolve(rule)
        if not matcher_def then goto continue end

        local matched = matcher.test(matcher_def, ctx)
        if not matched then goto continue end

        -- [C2] 速率限制检查（只有匹配的规则才检查）
        if not waf_manager.check_rate_limit(rule.id, rule) then
            goto continue
        end

        -- [C2] 记录命中统计（异步，非阻塞）
        waf_manager.record_hit(rule.id, ctx)

        local action = rule.action or "log"

        if action == "accept" then
            -- [Issue-5] accept 是白名单语义，清除残留 pending，避免下次误记 challenge_fail
            ip_reputation.clear_pending(ip)
            ctx.set_action(ctx, "accept")
            return true
        elseif action == "block" then
            -- [C3] 仅在 block 分支记录信号
            ip_reputation.record_signal(ip, "waf_block", ctx.request.uri)
            ctx.set_action(ctx, "block", { code = rule.code or 403, response = rule.response })
            return true
        elseif action == "challenge" then
            -- [C3] 仅在 challenge 分支记录信号
            ip_reputation.record_signal(ip, "waf_challenge", ctx.request.uri)
            -- ⚠️ 使用 is_flagged(ip, { no_cache = true }) 做实时判定，而非手动比较 get_score()：
            --    [Issue-2] is_flagged 内部统一应用 diversity_factor（get_score 已含），
            --              避免在两处重复实现阈值逻辑导致漂移。
            --    [Issue-4] is_flagged 内部同时检查 min_requests 门槛，
            --              避免此处绕过 min_requests。
            --    no_cache=true 跳过 10s 结果缓存，确保本次请求 record_signal 的累加立即生效；
            --    命中阈值时 is_flagged 内部自动调用 flag_ip（写冷却期 + flagged_index）。
            if ip_reputation.is_flagged(ip, { no_cache = true }) then
                ctx.set_action(ctx, "block", { code = 403, response = rule.response })
                return true
            end
            ip_reputation.set_pending(ip)
            -- ⚠️ 设置 action，由 rule_engine.apply 执行
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
    return false  -- no decision
end

function _M.on_access(ctx)
    local ip = ctx.request.remote_addr

    -- 【前置-1】管理路径放行（现有逻辑）
    local base_uri = (config and config.base_uri) or "/verynginx"
    if ctx.request.uri:find(base_uri, 1, true) == 1 then
        return
    end

    -- 【前置-0】请求计数 + UA 采集（在管理路径检查之后，避免 dashboard 流量污染）
    ip_reputation.increment_req(ip)
    ip_reputation.record_ua(ip, ctx.request.user_agent or "")

    -- 【前置-1.5】静态 IP 白名单 → 直接放行（新增）
    if ip_reputation.is_whitelisted(ip) then
        return
    end

    -- 【前置-3】IP 已被标记为扫描器 → 直接封禁（新增）
    if ip_reputation.is_flagged(ip) then
        ctx.set_action(ctx, "block", { code = 403, response = "forbidden_json" })
        return
    end

    -- 加载规则并按类型分组
    -- [C1] waf_manager.load_rules() 返回 { version, timestamp, rules = [...] }，非数组
    --     #all_rules 直接作用于该 table 永远是 0，必须解包 rules 字段
    local rules_obj = waf_manager.load_rules()
    local all_rules
    if rules_obj and rules_obj.rules and #rules_obj.rules > 0 then
        all_rules = rules_obj.rules
    else
        -- 回退到内置默认规则
        local fallback = require "plugin.filter.rules"
        all_rules = fallback.load_rules()
    end
    if not all_rules or #all_rules == 0 then
        return  -- 无规则时放行
    end
    local hard_block_rules, challenge_rules = split_rules(all_rules)

    -- 【阶段一】始终执行硬 block 规则（SQLi/RCE/path traversal/scanner UA）
    -- ⚠️ 不检查 cookie — block rules 必须始终执行！
    local decided = evaluate_rules(hard_block_rules, ctx, ip, waf_manager)
    if decided then
        return
    end

    -- 【⛔ 已弃用 — has_pending/challenge_fail 逻辑移至前置-2 之后】
    -- 旧顺序（M-a 问题）：先 challenge_fail 再 cookie 检查→clear_score，导致合法用户被扣分
    -- 新顺序：先检测 cookie → 有 cookie 则 clear_score 放行 → 无 cookie 且 has_pending 才 challenge_fail

    -- 【前置-2】检查 JS 验证 cookie
    -- ⚠️ 仅跳过 challenge-type 规则，硬 block 规则已在阶段一处理完毕
    local cookie_verified = javascript_verify.check(ctx)
    if cookie_verified then
        -- 已验证：清零分数，跳过后续 challenge 规则
        ip_reputation.clear_score(ip)
        ctx.set_data(ctx, "reputation:challenge_passed", true)
        return
    end

    -- 【检查 pending 状态】仅当无有效 cookie 时才有意义
    --    合法用户在请求 1 被设置 pending，请求 2 带 cookie 返回，不会到达此处
    --    仅扫描器才会无 cookie 到达此分支
    if ip_reputation.has_pending(ip) then
        ip_reputation.record_signal(ip, "challenge_fail", ctx.request.uri)
        ip_reputation.clear_pending(ip)
    end

    -- 【阶段二】无有效 cookie 时，执行 challenge 类规则
    decided = evaluate_rules(challenge_rules, ctx, ip, waf_manager)
    -- 如果 challenge 命中 → action 已设置 → TERMINAL_ACTIONS 中断后续插件
    -- 如果没有命中 → 正常放行
end
```

#### 3.2.2 默认规则调整 — `plugin/filter/rules.lua`

**关键变更**：UA 扫描器用 block（不可能误伤），路径探测用 challenge：

```lua
_M.default_rules = {
    { enable = true, matcher = "attack_sqli",           action = "block",     code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_backup",         action = "block",     code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_scanner",        action = "block",     code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_code_leak",      action = "challenge", code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_path_traversal", action = "block",     code = 403, response = "forbidden_json" },
    { enable = true, matcher = "attack_rce",            action = "block",     code = 403, response = "forbidden_json" },
}
```

**分界原则**（修改后更清晰）：

| 动作 | 适用场景 | 特征 |
|----------|----------|------|
| `block` | SQL注入、路径穿越、RCE、已知扫描器 UA | 不可能有合法用途，一个命中即可判定恶意 |
| `challenge` | 路径探测（`.git`、`/phpmyadmin`）、代码泄露探测 | 正常用户可能偶然访问，先验证再放行 |
| `log` | 可疑但不足以判定（如登录路径探测） | 仅记录，供后续分析 |
| `accept` | 明确放行的路径/IP | 白名单性质 |

#### 3.2.3 `core/rule_engine.lua` — 增加 challenge 动作

**⚠️ challenge 必须是 terminal action**，否则下游插件会覆盖它。需要在两个层面保障：

**（1）RESULT 表增加 CHALLENGE：**

```lua
local RESULT = {
    PASS = "pass",
    ACCEPT = "accept",
    BLOCK = "block",
    REWRITE = "rewrite",
    REDIRECT = "redirect",
    RESPONSE = "response",
    PROXY = "proxy",
    STATIC = "static",
    CHALLENGE = "challenge",  -- 新增
}
```

**（2）apply() 增加 challenge 分支：**

```lua
elseif action.type == RESULT.CHALLENGE then
    -- 在 pcall 之外安全调用 ngx.exit
    local javascript_verify = action.data.javascript_verify
        or require "plugin.browser_verify.javascript_verify"
    javascript_verify.challenge(ctx)
    -- ⚠️ challenge() 不再调用 ngx.exit(200)，由 apply() 统一终止
    return ngx.exit(200)
```

apply() 中 challenge 分支的位置应该放在 PROXY/STATIC 之后、ACCEPT 之前——作为终止流程，与其他 terminal action (block/redirect/response) 行为一致。

#### 3.2.4 `core/plugin.lua` — TERMINAL_ACTIONS 增加 challenge

**⚠️ 这是最容易被遗漏的改动。没有它，下游插件会覆盖 challenge 动作。**

plugin.lua execute_access 的循环检查：
```lua
if ctx.has_decision(ctx) and _M._is_terminal(ctx) then
    break
end
```

`_is_terminal()` 检查的是 `TERMINAL_ACTIONS` 表：
```lua
local TERMINAL_ACTIONS = { block = true, redirect = true, response = true, challenge = true }
```

**如果不加 `challenge = true`：**
```
filter(100)   → match attack_code_leak → set_action("challenge") → return
frequency_limit(200) → 继续执行 → 可能 set_action("block") → 覆盖 challenge
browser_verify(300)  → 继续执行 → 可能 set_action(...) → 覆盖
router(400)   → 继续执行 → 可能 set_action("proxy") → 覆盖 challenge！
proxy_pass(500) → 继续执行 → set_action("proxy", {host="backend"}) → challenge 被彻底覆盖

→ 最终 rule_engine.apply() 执行的是 proxy，不是 challenge
→ 用户看不到 challenge 页面，直接被代理到后端
```

**加上 `challenge = true` 后：**
```
filter(100)   → match attack_code_leak → set_action("challenge") → return
frequency_limit(200) → _is_terminal(ctx)=true → break ✓
browser_verify(300) → 跳过 ✓
router(400)   → 跳过 ✓
proxy_pass(500) → 跳过 ✓

→ rule_engine.apply() 执行 challenge → 返回 challenge HTML ✓
```

**结论**：不修改 TERMINAL_ACTIONS 等同于 challenge 动作从未存在，所有设计都白费。

#### 3.2.5 browser_verify 插件同步改为 set_action 模式

browser_verify 插件当前直接调用 `javascript_verify.challenge()` 或 `ngx.redirect()`，虽然 OpenResty 的 pcall 重写使 ngx.exit 能正常工作，但为了**架构一致性**（所有终止动作统一由 rule_engine.apply 落地），建议同步修改：

- `plugin/browser_verify/init.lua`：不再直接调用 `challenge()` 或 `redirect()`，改为 `ctx.set_action(ctx, "challenge", { type = "javascript" })` 或 `ctx.set_action(ctx, "challenge", { type = "cookie" })`
- `action/data` 携带验证类型：
  - `{ type = "javascript", javascript_verify = js_mod }` → 走 JS challenge
  - `{ type = "cookie" }` → 走 cookie_verify 的 302 redirect
- `rule_engine.apply()` 根据 `action.data.type` 分发到不同的验证器

由于 browser_verify 的 `default_enable = false` 且此次改动不影响 filter 的核心路径，**这不是关键路径的阻塞项，可以先实现 filter 的 challenge 再补 browser_verify 的同步**。

#### 3.2.6 Challenge 失败信号的闭环（修正版）

**原方案的问题**：在 log 阶段检测"挑战是否失败"不可行，因为：
1. log 阶段无法区分 challenge 页面和正常响应的 200
2. "后续请求"与当前请求的生命周期完全隔离

**修正后的方案**：跨请求 pending 状态 + 下一次的请求检测

```
pending 状态管理：
┌─────────────────────────────────────────────────────────────────┐
│  请求 1: GET /phpmyadmin/（无 cookie）                           │
│    filter: 无 pending → 匹配规则 → set_pending(ip) +           │
│            ctx.set_action(ctx, "challenge", { ... })            │
│    → rule_engine.apply() 在 pcall 之外调用 challenge()           │
│    → ngx.exit(200) 返回 challenge HTML                          │
│                                                                  │
│  请求 2: GET /phpmyadmin/（扫描器无 cookie / 浏览器有 cookie）   │
│    filter: javascript_verify.check(ctx)                          │
│      ├─ 浏览器（有 cookie）→ true → return 放行                  │
│      └─ 扫描器（无 cookie）→ false                               │
│        filter: has_pending(ip) = true → record_signal(challenge_fail, +5) │
│        clear_pending(ip)                                        │
│        → 重新匹配规则 → 超阈值 → block                          │
└─────────────────────────────────────────────────────────────────┘
```

#### 3.2.7 `plugin/summary/init.lua` — 404 采集 + 统计排除

函数体内部 require。改为模块级 require：

```lua
local statistics = require "core.statistics"
local ip_reputation = require "core.ip_reputation"
local javascript_verify = require "plugin.browser_verify.javascript_verify"

function _M.on_log(ctx)
    -- 跳过 challenge 响应的统计（避免污染正常数据）
    -- 使用 ctx.data 机制，与 codebase 风格一致
    if ctx.get_data(ctx, "reputation:challenge_response") then
        return
    end

    statistics.log_request(ctx)

    -- IP 声誉信号采集：404 响应
    -- ⚠️ 仅对没有有效 challenge cookie 的 IP 计数 404
    --    有 cookie 的合法用户偶然遇到 404（SPA 路由、监控探测）不应被惩罚
    local status = tonumber(ngx.var.status) or 0
    if status == 404 then
        if not javascript_verify.check(ctx) then
            local uri = ctx.request.uri or ngx.var.uri or ""
            ip_reputation.record_signal(ctx.request.remote_addr, "not_found", uri)
        end
    end
end
```

仅在 filter 的 challenge 处理中通过 `ctx.set_data(ctx, "reputation:challenge_response", true)` 标记，通知 summary 跳过该请求的统计。不需要修改 core/statistics.lua。

#### 3.2.8 `plugin/browser_verify/javascript_verify.lua` — sign() 保持不变

**核心变更**：challenge() 不再直接调用 `ngx.exit`，改为设置 action 让 rule_engine.apply 统一处理。

```lua
--- sign() 保持当前实现不变 ---
local function sign(ctx, mark)
    local ua = ngx.var.http_user_agent or ""
    local seed = (config.security and config.security.session_secret) or _fallback_seed
    return ngx.md5("VN" .. ctx.request.remote_addr .. ua .. mark .. seed)
end
```

**⚠️ 注意：challenge() 的调用方式变更**

challenge() 仍然输出 challenge HTML，但**不能再直接调用 `ngx.exit(200)`**。
在 filter 插件中，challenge 动作通过 `set_action("challenge", ...)` 设置，
由 rule_engine.apply() 在 pcall 之外调用，ngx.exit 才能正常生效。

```lua
function _M.challenge(ctx)
    -- ... 现有 HTML 生成逻辑 ...

    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-cache, no-store, must-revalidate"
    -- 注意：不添加 ngx.header["Set-Cookie"]，保持 JS 验证的纯粹性

    ngx.say(html)
    -- ⚠️ 不再调用 ngx.exit(200) - 由 rule_engine.apply() 调用此函数
    --    rule_engine.apply 在 pcall 之外运行，ngx.exit 正常终止请求
end
```

---

## 四、完整请求流程示例（修正版）

### 4.1 正常用户访问 phpMyAdmin

```
请求 1（首次访问，无 cookie）:
  ├─ 管理路径检查 → 继续
  ├─ 白名单检查 → 跳过
  ├─ is_flagged → false
  ├─ 【阶段一】硬 block 规则 evaluate_rules:
  │   ├─ attack_sqli → 不匹配（URI 上无参数）
  │   ├─ attack_path_traversal → 不匹配
  │   ├─ attack_rce → 不匹配
  │   └─ attack_scanner → 不匹配（UA 正常）
  ├─ has_pending → false
  ├─ JS cookie 验证 → false（无 cookie）
  ├─ 【阶段二】challenge 规则
  │   └─ attack_code_leak → 匹配（URI 类似 /.git/config 或 /admin/.env 等敏感路径）
  │       └─ 即使请求路径是 /phpmyadmin，默认的 attack_code_leak 规则
  │          正则不包含 /phpmyadmin；实际部署需要根据站点增加自定义规则
  │          本例用 attack_code_leak 示意 challenge 流程，不特指具体路径
  │       ├─ record_signal(ip, "waf_challenge") → score +3
  │       ├─ set_pending(ip)
  │       └─ ctx.set_action("challenge", { ... })
  ├─ rule_engine.apply(ctx, "access") → challenge 分支
  │   └─ javascript_verify.challenge(ctx) → ngx.exit(200)
  └─ [请求终止，浏览器收到 challenge HTML]

浏览器执行 JS:
  ├─ 设置 cookie: verynginx_sign_javascript=<md5>
  └─ 跳转到: http://server/phpmyadmin/

请求 2（带 cookie，自动跳转）:
  ├─ 管理路径检查 → 继续
  ├─ 白名单检查 → 跳过
  ├─ is_flagged → false
  ├─ 【阶段一】硬 block 规则 evaluate_rules → 全部不匹配 ✓
  │   （attack_sqli/path_traversal/rce/scanner 全部执行，但都不命中）
  ├─ has_pending → false
  ├─ JS cookie 验证 → true（cookie 有效）
  ├─ clear_score(ip) → 清除历史分数，防止长期累积
  ├─ return 放行（跳过 challenge 规则，但 block 规则已执行）✓
  ├─ proxy_pass → 后端 phpMyAdmin
  └─ 用户正常访问 ✓

⚠️ 即使请求 2 携带 cookie，阶段一的 block 规则仍然执行。
   如果攻击者在 cookie 有效后发送 SQLi payload → attack_sqli 匹配 → 直接 block 403。

请求 3~N（后续请求，cookie 仍在有效期内）:
  └─ 同上：阶段一 block 规则始终执行 → cookie 仅跳过 challenge 规则
  └─ Cookie 有效期 600s（Max-Age），到期后需重新 JS 验证 |
```

### 4.2 扫描器/攻击者探测 phpMyAdmin

**场景 A — 普通扫描器（无 JS 执行能力）**

```
请求 1: GET /phpmyadmin/
  ├─ 【阶段一】硬 block 规则 → 无匹配（路径安全）
  ├─ 无 cookie
  ├─ 【阶段二】challenge 规则 → attack_code_leak 匹配
  ├─ waf_challenge +3, set_pending(ip), challenge() → 200
  └─ [扫描器无法执行 JS]

请求 2: GET /phpmyadmin/ (再次探测，仍无 cookie)
  ├─ 【阶段一】硬 block 规则 → 无匹配
  ├─ 【前置-2】JS cookie 验证 → false（无 cookie）
  ├─ has_pending = true → challenge_fail +5, clear_pending
  ├─ 【阶段二】challenge → attack_code_leak 匹配
  ├─ waf_challenge +3, set_pending, challenge() → 200
  └─ [继续无 cookie]

请求 3~4: 继续挑战 → 每轮 challenge_fail +5 + waf_challenge +3
  ├─ 请求 3: score = 11 + 5 + 3 = 19
  ├─ 请求 4: score = 19 + 5 + 3 = 27 ≥ 25 → flag_ip(ip, 600) → IP 标记
  └─ 后续请求：is_flagged → 直接 403（冷却期 600s）
```

**场景 B — 高级攻击者（使用真实浏览器获取 cookie 后发送攻击）**

```
阶段 1: 攻击者用浏览器访问 /phpmyadmin/ → 执行 JS → 获得 cookie

阶段 2: 攻击者用同一浏览器发送攻击 (id=1' OR 1=1; DROP TABLE users;--)
  ├─ 【阶段一】硬 block 规则
  │   └─ attack_sqli 匹配！→ record_signal(waf_block, +5)
  │   └→ set_action("block", { code = 403 }) → return ✗
  │
  ├─ JS cookie 检查 ← 永远不会执行到这里！
  │
  └─ [请求被 block，攻击失败] ✓

【安全关键】block 规则在 cookie 检查之前执行，cookie 不能绕过 SQLi/RCE 防护
```




### 4.3 共享 NAT IP 的用户 A（正常）+ 用户 B（扫描器）

```
用户 A（正常）首次访问:
  ├─ IP = 1.2.3.4, UA = Chrome/120
  ├─ record_signal(waf_challenge) +3 → score=3
  ├─ challenge → JS cookie 设置 → clear_score(ip)
  └─ 后续访问：cookie 有效 → clear_score → 永远不被标记 ✓

用户 B（扫描器）从同一 IP 发起:
  ├─ IP = 1.2.3.4, UA = python-requests/2.28（不同 UA）
  ├─ diversity_factor = max(0.5, 1.0 - (2-1) * 0.1) = 0.9
  ├─ 用户 A 的 cookie 存在 → 用户 A 继续放行（不受影响）
  └─ 用户 B 无 cookie → challenge → 失败 → score 累积

如果用户 B 导致 IP 被标记:
  ├─ 用户 A 已被 cookie 保护 → javascript_verify.check 通过 → clear_score → 放行 ✓
  ├─ 用户 A cookie 已过期/清除 → 被 block
  │   └─ Dashboard 展示"IP 被 block，原因：ip_reputation_threshold"
  │   └─ 用户 A 可点击"申请解除" → 管理员确认后加白名单
  └─ 用户 B 继续被 block，冷却期 600s 后重新进入 challenge 流程

> **注**：用户 B 导致 score ≥ threshold 时，challenge 分支自动调用 `flag_ip(ip, flag_duration)`，
> 写入 `ip_rep:flagged:<ip>` 并更新 `flagged_index`。后续请求在前置-3 检查
> `is_flagged` 时直接命中冷却期缓存，无需重新计分。冷却期 600s 到期后
> `ip_rep:flagged:<ip>` 过期，IP 重新进入 challenge 流程。
```

---

## 五、需要改动的文件清单

| 文件 | 改动类型 | 说明 |
|------|----------|------|
| `core/ip_reputation.lua` | **新建** | IP 声誉评分引擎（含 pending 状态管理、diversity_factor、UA 跟踪、is_flagged 缓存） |
| `nginx_conf/in_http_block.conf` | 修改 | 新增 `lua_shared_dict ip_reputation 16m;` |
| `plugin/filter/init.lua` | **重大修改** | 两阶段规则评估（硬 block 始终执行 + challenge 规则可跳过）、前置-0（req/ua 计数）、前置-1.5（白名单）、前置-2（cookie 验证 + clear_score） |
| `plugin/filter/rules.lua` | 修改 | attack_scanner 保持 block，attack_code_leak 改 challenge |
| `plugin/summary/init.lua` | 修改 | log 阶段采集 404 信号 + 排除 challenge 响应的 statistics 统计 |
| `plugin/browser_verify/javascript_verify.lua` | 修改 | sign() 保持不变；challenge() 改为由 rule_engine.apply 调用（架构一致性）；**反射进 HTML 的 uri/host/query 必须做 JS 字符串转义（见 8.1.1，防反射型 XSS）** |
| `plugin/browser_verify/cookie_verify.lua` | 修改 | 改为 set_action("challenge", { type = "cookie" }) 走 rule_engine（架构一致性） |
| `plugin/browser_verify/init.lua` | **修改** | 改为 set_action("challenge")，action.data.type 携带验证类型 |
| `core/statistics.lua` | 无修改 | challenge 响应跳过统计的逻辑已整合到 summary/init.lua 中（通过 ctx.set_data 通信），无需改动 statistics.lua |
| `core/config.lua` | 修改 | schema 增加 `ip_reputation` 配置字段 |
| `core/plugin.lua` | **修改** | `TERMINAL_ACTIONS` 增加 `challenge = true` — 防止下游插件覆盖 challenge 动作 |
| `core/rule_engine.lua` | **修改** | RESULT 表增加 CHALLENGE；apply() 增加 challenge 分支（在 pcall 之外安全调用 challenge） |
| `api/init.lua` | 修改 | 增加 IP 声誉查询/操作 API（list、clear、whitelist、stats） |
| `core/init.lua` | 修改 | init_worker 中初始化 ip_reputation 定时器 + restore |
| `dashboard/index.html` | 修改 | IP 声誉面板（已标记列表 + 手动管理 + 实时分数图） |
| `test/v2/spec/ip_reputation_spec.lua` | **新增** | 单元测试（信号采集、is_flagged、diversity_factor、持久化） |
| `test/v2/spec/filter_challenge_spec.lua` | **新增** | 集成测试（正常用户流程、扫描器流程、WHITELIST 流程） |
| `test/v2/spec/rule_engine_challenge_spec.lua` | **新增** | rule_engine challenge 动作的 apply 测试 |
| `test/v2/spec/plugin_terminal_actions_spec.lua` | **新增** | TERMINAL_ACTIONS 包含 challenge 的验证测试 |
| `test/v2/spec/security_cookie_bypass_spec.lua` | **新增** | **关键安全测试**：验证 JS cookie 不能绕过 block 规则（SQLi/RCE/path traversal 始终被 block） |
| `test/v2/spec/security_challenge_xss_spec.lua` | **新增** | **关键安全测试**：验证 challenge HTML 反射的 uri/host/query 已转义，恶意输入不产生可执行脚本（见 8.1.1） |
| `support/verify_javascript.html` | **修改** | Cookie 设置改为 `document.cookie='...; Max-Age=600; SameSite=Strict'`（移除硬编码 365 天持久化） |

---

## 六、配置示例

```json
{
  "ip_reputation": {
    "enable": true,
    "threshold": 25,
    "flag_duration": 600,
    "window_size": 300,
    "slot_size": 60,
    "min_requests": 3,
    "pending_ttl": 600,
    "diversity_factor_enable": true,
    "signals": {
      "waf_challenge": 3,
      "waf_block": 5,
      "not_found": 1,
      "challenge_fail": 5
    },
    "whitelist": [],
    "persist_enable": true,
    "persist_interval": 600,
    "log_level": "WARN"
  }
}
```

---

## 七、API 设计（新增）

### 7.1 内部 API（Lua 间调用）

```lua
-- 已经在 2.6 节列出
ip_reputation.increment_req(ip)
ip_reputation.record_ua(ip, ua_string)
ip_reputation.record_signal(ip, signal_type, uri)
ip_reputation.is_flagged(ip, opts)
ip_reputation.get_score(ip)
ip_reputation.set_pending(ip)
ip_reputation.has_pending(ip)
ip_reputation.clear_pending(ip)
ip_reputation.flag_ip(ip, duration)
ip_reputation.clear_ip(ip)
ip_reputation.clear_score(ip)
ip_reputation.add_whitelist(ip)
ip_reputation.remove_whitelist(ip)
ip_reputation.is_whitelisted(ip)
ip_reputation.list_flagged()
ip_reputation.list_whitelist()
ip_reputation.get_stats()
ip_reputation.persist()
ip_reputation.restore()
```

### 7.2 HTTP API（Dashboard 调用）

```
GET  /verynginx/api/reputation/stats          → 全局统计
GET  /verynginx/api/reputation/flagged        → 已标记 IP 列表
GET  /verynginx/api/reputation/whitelist      → 白名单列表
GET  /verynginx/api/reputation/score/<ip>     → 单 IP 详情（score、signals、pending）

POST /verynginx/api/reputation/clear/<ip>     → 手动解除标记
POST /verynginx/api/reputation/whitelist      → 加入白名单
DELETE /verynginx/api/reputation/whitelist/<ip> → 移出白名单
POST /verynginx/api/reputation/persist        → 触发持久化
```

---

## 八、安全加固措施

### 8.1 Challenge Cookie 生命周期（一致的 TTL 故事）

**TL;DR — 数字要对齐：所有 TTL 都是 600s（10 分钟）**

| 组件 | 位置 | TTL | 作用 |
|------|------|-----|------|
| **Cookie** | 客户端浏览器 | `Max-Age=600` | 浏览器在 600s 内免重新验证 |
| **pending 状态** | 服务端 shared dict | `pending_ttl=600s` | 服务端在 600s 内检测 challenge 是否被浏览器回传（与 cookie Max-Age 对齐） |
| **验证签名** | sign() 函数 | **不含时间分量** | 签名由 IP+UA+seed 决定，不随时间变化 |

**核心安全约束**：JS Challenge 必须仅通过 `document.cookie=` 设置 cookie，**不能同时使用 `Set-Cookie` HTTP 头**。否则：

> curl 等带 cookie jar 的 HTTP 客户端可以跳过 JS 执行，直接通过 `Set-Cookie` 头获取 cookie 并回传，使 challenge 降级为简单的 cookie 校验，丧失区分浏览器与自动化工具的能力。

**Cookie 属性**（challenge HTML 中 JS 设置）：
```javascript
document.cookie = 'verynginx_sign_javascript=' + hash + '; Path=/; SameSite=Strict; Max-Age=600';
```

- `Max-Age=600`：cookie 在 600s 后由浏览器自动删除
- `Path=/`：cookie 对所有路径有效
- `SameSite=Strict`：禁止跨站携带（降低 CSRF 风险）
- **不设置 HttpOnly**：JS cookie 不可能是 HttpOnly（这是浏览器执行 JS 的证明）

**不设置 HttpOnly 的安全分析**：
- 恶意 JS 可以读取此 cookie（XSS 攻击），但此时攻击者已在用户浏览器中执行 JS，可以直接执行网络请求，不需要窃取 cookie
- 签名绑定了 IP+UA，即使 cookie 泄露，攻击者需要相同的 IP+UA 才能使用
- 服务器端 pending_ttl=600s 提供二级保护：如果攻击者在 600s 内不活跃，pending 过期

**补充安全建议**：
- 确保 `session_secret` 高熵（>= 32 字节），定期更换
- 如果 nginx 前面有 CDN/反代，确保 CDN 不缓存 challenge 页面（已设置 `Cache-Control: no-cache`）

### 8.1.1 Challenge HTML 输出安全（防反射型 XSS）

**⚠️ 高优先级 — 实现前必须解决。**

`javascript_verify.challenge()` 会把请求信息反射进 challenge HTML 模板：

```lua
-- 现有实现：target 由用户可控字段拼接
local target = ctx.request.scheme .. "://" .. ngx.var.http_host .. ctx.request.uri
if ngx.var.query_string and ngx.var.query_string ~= "" then
    target = target .. "?" .. ngx.var.query_string
end
-- 注入模板：'uri' : "INFOURI"  →  用于 window.location = data['uri']
html = util.string_replace(html, "INFOURI", target, 1)
```

`ctx.request.uri`、`ngx.var.query_string`、`ngx.var.http_host` **均为客户端可控**，且落点在 JS 字符串上下文（`"INFOURI"`）。攻击者构造包含 `"`、`</script>`、`\` 等字符的 URI/query，可突破字符串上下文，形成**反射型 XSS**。8.1 只讨论了 cookie 安全，未覆盖此输出面。

**修复要求（实现阶段落实）**：

1. **对反射值做 JS 字符串转义**，再注入模板。至少转义 `"`、`'`、`\`、`<`、`>`、`/`、换行、以及 `</script`：
   ```lua
   local function js_string_escape(s)
       if not s then return "" end
       return (s:gsub('[\\"\'<>/\r\n]', {
           ['\\']='\\\\', ['"']='\\x22', ["'"]='\\x27',
           ['<']='\\x3C', ['>']='\\x3E', ['/']='\\x2F',
           ['\r']='\\r', ['\n']='\\n',
       }))
   end
   -- target = js_string_escape(target) 后再 string_replace
   ```
   或更稳妥：用 `require("dkjson").encode(target)` 生成合法 JS 字符串字面量，避免手写转义遗漏。
2. **`http_host` 校验**：优先使用 nginx `server_name` 白名单或已知 Host，而非直接反射 `ngx.var.http_host`（防 Host 头注入）。
3. **跳转目标做协议白名单**：`window.location` 仅允许 `http://` / `https://` / 同源相对路径，拒绝 `javascript:` 等伪协议。
4. 响应头补充 `X-Content-Type-Options: nosniff`；如条件允许，为 challenge 页面下发严格 CSP（如 `script-src 'unsafe-inline'` 最小化）。

**测试要求**：在 `test/v2/spec/security_cookie_bypass_spec.lua`（或新增 `security_challenge_xss_spec.lua`）中增加用例：构造带 `"><script>` / `";alert(1)//` 的 URI 与 query，断言输出 HTML 中反射值已被转义，不产生可执行脚本。

### 8.2 签名保持简单（不添加时间分量）

**设计决策：sign() 不添加时间分量**

当前实现（保持不变）：
```lua
local function sign(ctx, mark)
    local ua = ngx.var.http_user_agent or ""
    local seed = (config.security and config.security.session_secret) or _fallback_seed
    return ngx.md5("VN" .. ctx.request.remote_addr .. ua .. mark .. seed)
end
```

**为什么不加 time_slot？**

| 方案 | 优点 | 缺点 |
|------|------|------|
| **加 time_slot**（如 /3600） | Cookie 定期轮换，泄露窗口缩短 | 1. 每次部署使所有 browser_verify JS cookie 失效<br>2. 每 1-2 小时用户被重新挑战（违背"透明、无感"）<br>3. sign() 签名变更需 nginx reload |
| **不加 time_slot**（当前） | 1. 签名稳定，部署不失效<br>2. 用户在 cookie TTL 内无需重新挑战<br>3. sign() 逻辑简单，无需处理时间窗口对齐 | Cookie 泄露后有效期 = 600s（而非 1 小时），但 IP+UA 绑定限制了泄露利用 |

**结论**：选择**不加 time_slot**，因为：
- 安全性足够：IP+UA 绑定 + 600s TTL + 服务器端 pending 检测
- 用户体验最佳：最长免挑战窗口
- 部署平稳：不影响现有 cookie

### 8.3 防御 Determined Attacker

针对知道 seed 的定向攻击者：

- `session_secret` 必须具备高熵（>= 32 字节），定期更换
- 签名加入 IP + UA 绑定，即使 attacker 获取 seed+时间片 cookie，也需要相同的 IP+UA 对
- Dashboard 展示被封 IP 的 UA 分布，管理员可识别伪造行为

---

## 九、持久化与可靠性

### 9.1 flagged 列表持久化

nginx 重启会导致 shared dict 数据丢失。将 `flagged` 列表定期写入磁盘。持久化记录格式：

```json
{
    "ip": "1.2.3.4",
    "flagged_at": 1719840000,
    "expires_at": 1719840600,
    "score_at_flag": 27,
    "distinct_ua_count": 2
}
```

其中 `expires_at = flagged_at + flag_duration`，restore 时只恢复尚未过期的记录。

```lua
-- 维护 flagged_index（在 flag_ip/clear_ip 时同步更新）
local function add_to_flagged_index(ip, duration)
    local shared = ngx.shared.ip_reputation
    local index_raw = shared:get("ip_rep:flagged_index") or "{}"
    local ok, index = pcall(require("dkjson").decode, index_raw)
    if not ok or type(index) ~= "table" then index = {} end
    -- 检查是否已存在
    for _, entry in ipairs(index) do
        if entry.ip == ip then return end
    end
    table.insert(index, {
        ip = ip,
        flagged_at = ngx.time(),
        expires_at = ngx.time() + (duration or 600)
    })
    shared:set("ip_rep:flagged_index", require("dkjson").encode(index))
end

-- list_flagged 直接读取 index（避免 get_keys() 全量扫描）
function _M.list_flagged()
    local shared = ngx.shared.ip_reputation
    local index_raw = shared:get("ip_rep:flagged_index")
    if not index_raw or index_raw == "" then return {} end
    local ok, index = pcall(require("dkjson").decode, index_raw)
    if not ok or type(index) ~= "table" then return {} end
    -- 过滤已过期条目
    local now = ngx.time()
    local valid = {}
    for _, entry in ipairs(index) do
        if entry.expires_at and entry.expires_at > now then
            table.insert(valid, entry)
        end
    end
    return valid
end

function _M.persist()
    local flagged = _M.list_flagged()
    if #flagged == 0 then return end

    local path = require("core.config").resolve_path() .. "/configs/ip-reputation-flagged.json"
    local tmp = path .. ".tmp"
    local f = io.open(tmp, "w")
    if not f then return end
    f:write(require("dkjson").encode(flagged, { indent = true }))
    f:close()
    os.rename(tmp, path)
end

function _M.restore()
    -- 仅在 worker 0 执行
    if ngx.worker.id and ngx.worker.id() ~= 0 then return end

    local path = require("core.config").resolve_path() .. "/configs/ip-reputation-flagged.json"
    local f = io.open(path, "r")
    if not f then return end
    local data = f:read("*all")
    f:close()
    local ok, flagged = pcall(require("dkjson").decode, data)
    if not ok or type(flagged) ~= "table" then return end

    local shared = ngx.shared.ip_reputation
    local now = ngx.time()
    local valid_entries = {}
    for _, entry in ipairs(flagged) do
        if entry.expires_at and entry.expires_at > now then
            local remaining = entry.expires_at - now
            shared:set("ip_rep:flagged:" .. entry.ip, entry.flagged_at, remaining)
            table.insert(valid_entries, entry)
        end
    end
    -- 重建 index（只包含有效条目）
    shared:set("ip_rep:flagged_index", require("dkjson").encode(valid_entries))
end
```

### 9.2 `core/init.lua` 初始化入口

> **注意**：此方案替代了旧版独立定时器方案。定时器逻辑直接集成到 core/init.lua 的 init_worker 中，避免独立模块的双注册陷阱。**切勿同时实现多个定时器注册路径。**

在 `core/init.lua` 中增加 ip_reputation 的初始化调用。分为两个入口：

**init_by_lua — 启动时加载持久化数据：**

```lua
-- core/init.lua 中的 init() 函数增加：
function _M.init()
    config.load_from_file()
    _M.init_shared_dict()
    _M._validate_config()
    _M.register_matchers()
    _M.register_plugins()
    plugin.init_all()

    -- 新增：恢复已持久化的 IP reputation 数据
    local ip_reputation = require "core.ip_reputation"
    ip_reputation.restore()
end
```

**init_worker_by_lua — 在每个 worker 中启动定时器（仅 worker 0 实际执行 I/O）：**

```lua
-- core/init.lua 中的 init_worker() 函数增加：
function _M.init_worker()
    local metrics = require "core.metrics"
    local observability = require "core.observability"
    local statistics = require "core.statistics"
    local health_check = require "plugin.proxy_pass.health_check"
    local waf_manager = require "waf-rule-manager"

    metrics.init()
    observability.init()
    statistics.init()
    health_check.init()
    waf_manager.init_worker()

    -- 新增：启动 ip_reputation 持久化定时器（仅 worker 0 执行）
    -- ⚠️ 仅注册 IP 声誉自身的 persist 定时器。
    --    flush_hit_stats/persist_recent_hits/restore_recent_hits 属于 WAF 命中统计，
    --    已由上面的 waf_manager.init_worker() 内部注册，切勿在此重复注册（会导致双倍执行）。
    local ip_reputation = require "core.ip_reputation"
    if ngx.worker.id() == 0 then
        ngx.timer.every(600, function()
            ip_reputation.persist()
        end)
    end
end
```

---

## 十、边界场景与限制

### 10.1 共享 IP（NAT/CGNAT）

| 场景 | 风险 | 缓解措施 |
|------|------|----------|
| 公司/学校出口 IP | 一人扫描导致全员被封 | diversity_factor、manual unblock、whitelist |
| 移动运营商 CGNAT | 同上 | 同上，建议移动端用户使用 DoH/DoT |
| 公共 WiFi | 同上 | 同上 |

### 10.2 与 frequency_limit 的交互

| 优先级 | 插件 | 场景 |
|--------|------|------|
| 100（先） | filter (WAF) | 内容型攻击：SQLi/XSS/路径探测，challenge 或 block |
| 200（后） | frequency_limit | 频率型攻击：单 IP 超高 QPS 限流 |

两者**执行顺序是 filter 先、frequency_limit 后**（core/plugin.lua 按优先级升序排列，数值越小越先执行）。一个请求先经过 WAF 规则匹配，再经过频率限制。两者互补：
- filter 拦内容攻击（低频但恶意 payload）
- frequency_limit 拦流量攻击（高频并发请求）

### 10.3 反向代理/X-Forwarded-For 场景

当 VeryNginx 位于 CDN、WAF、负载均衡器之后时，`remote_addr` 是上游 IP，而非真实客户端 IP。IP 声誉体系依赖获取正确的客户端 IP。

**部署建议**：

```nginx
# nginx.conf 中配置可信代理 IP
set_real_ip_from 10.0.0.0/8;    # 内网代理网段
set_real_ip_from 172.16.0.0/12; # Docker 网段
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

如果无法正确配置 `real_ip`，IP 声誉将对所有经过同一代理的请求归于同一个 IP，导致严重误伤。在此场景下建议：
- 禁用单 IP 信誉体系，仅使用路径白名单 + challenge 规则
- 或使用代理协议（如 PROXY protocol）传递原始 IP

### 10.4 已知限制

1. **纯 API 客户端无法通过 JS challenge** — 如果 phpMyAdmin 有非浏览器客户端（如 REST API），需要为这些客户端的 UA/IP 配置白名单
2. **Tor 出口节点无法被封** — Tor 每次请求出口 IP 不同，单 IP 信誉体系失效。建议对 Tor 出口 UA（通常为默认浏览器 UA）做行为模式检测
3. **慢速扫描（Low and Slow）** — 如果扫描器故意降低频率，永远无法达到 threshold。此时更依赖 behavior-based detection（如短时间内访问多个敏感路径而非单一高频）
4. **IPv6 隐私地址** — IPv6 隐私扩展地址定期变化，使同一客户端的 IP 频繁变化。建议对 IPv6 /64 前缀进行信誉评估（而非完整地址），或对 IPv6 放宽 threat 阈值
5. **Diversity factor 自规避风险** — 扫描器可通过高频切换 User-Agent（≥6 种）将自身评分减半（factor=0.5），延迟检测到标记所需的请求数。这不是完全规避——只是将达到阈值所需的请求翻倍（如从 4→8 次），且 `ua_seen` 键无上限管理。**实现中必须设置 UA distinct 计数上限（建议 max_ua_distinct=20）**，超过后不再计入 diversity_factor，防止 unbounded key 膨胀。

### 10.5 监控告警

建议在以下情况输出日志：

- `ngx.WARN`：IP 被标记为扫描器 — `"ip_reputation: IP ", ip, " flagged as scanner, score=", score, " ua=", ctx.request.user_agent`
- `ngx.WARN`：challenge 发放和挑战失败记录（采样率 10%，避免高频扫描时日志溢出）
- `ngx.ERR`：每分钟 flag 数量超过阈值（如 100 个/分钟）— 可能表明大规模扫描或误配置，需要管理员介入

Dashboard 中展示以下统计指标：
- 当前 flagged IP 数量
- 当前 pending challenge 数量
- 今日/本周封禁总数
- 封禁原因分布（challenge_fail 为主 vs waf_block 为主）
- Top 10 被封 IP

---

## 十一、方案优势

1. **完全复用现有机制** — shared dict、browser_verify 的 JS challenge、WAF 规则管理系统，不引入新依赖
2. **用户体验最优** — 正常用户最多一次 JS 验证跳转（浏览器自动完成，几乎无感），后续 cookie 有效期内完全透明
3. **渐进式封禁** — 不一次封禁可疑 IP，而是通过多维度信号积累判定，大幅降低误杀
4. **Cookie 闭环可靠** — 通过 pending 状态 + 下一次请求检测，确保 challenge 失败能被精准记录
5. **NAT 感知** — diversity_factor 对共享 IP 的评分打折，降低集体惩罚风险
6. **自适应衰减** — 旧信号自动过期，被封禁 IP 在冷却期后可自动恢复
7. **可观测** — Dashboard 展示 IP 声誉状态，支持管理员手动操作
8. **防伪造** — IP+UA 绑定签名，即使 cookie 泄露，攻击者需要相同的 IP+UA 对才能使用
9. **持久化** — flagged 列表写入磁盘，nginx 重启后仍有效
10. **高性能** — `is_flagged()` 结果缓存 10 秒，避免每次请求遍历 25+ shared dict key；pending/challenge 状态全由 shared dict 维护，零文件 I/O
11. **防误封闭环** — 合法用户验证通过后 `clear_score(ip)` 清除历史分数，phpMyAdmin 长期用户永不误封
12. **硬 block 规则不可绕过** — SQLi/RCE/path traversal 防护始终生效，不因 JS cookie 验证通过而跳过（安全回归防护）
---

## 附录 A：内存估算

假设高峰期 50,000 请求/分钟，其中 5% 来自不同 IP（2,500 IP）：

| Key 格式 | 估算 |
|------|------|
| `ip_rep:waf:<ip>:<slot>` | 2500 IP × 5 slots × (35B key + 8B val) ≈ 540 KB |
| `ip_rep:404:<ip>:<slot>` | 同上 ≈ 540 KB |
| `ip_rep:challenge_fail:<ip>:<slot>` | 同上 ≈ 430 KB |
| `ip_rep:req:<ip>:<slot>` | 同上 ≈ 540 KB |
| `ip_rep:ua_count:<ip>:<slot>` | 同上 ≈ 540 KB |
| `ip_rep:ua_seen:<ip>:<slot>:<hash>` | 2500 IP × 5 slots × 10 hashes × (50B key + 8B val) ≈ 240 KB |
| `ip_rep:pending:<ip>` | 2500 IP × (30B + 8B) ≈ 95 KB |
| `ip_rep:flagged:<ip>` | 50 × (30B + 8B) ≈ 2 KB |
| `ip_rep:cache:<ip>` | 2500 IP × (25B + 8B) ≈ 82 KB |
| `ip_rep:flagged_index` | 1 × (~5 KB) ≈ 5 KB |
| `ip_rep:flagged_today` | 1 × (20B) ≈ 20 B |
| 总计 | ≈ 3.0 MB |

考虑大流量场景（10,000 活跃 IP，各 IP 平均 5 种不同 UA），新增 ua_seen 约 240 KB，总计约 12.2 MB，16MB shared dict 足够（预留 3.8 MB 余量）。

---

## 附录 B：与 DESIGN_V2.md 的兼容性

本方案完全兼容现有 DESIGN_V2.md 架构：

- 不修改 matcher/action 系统的核心接口
- 不新增 nginx 模块依赖
- 复用 browser_verify 的 JS challenge 实现（签名保持不变，cookie TTL 通过 JS Max-Age 控制为 600s）
- 复用 existing shared dict 管理策略
- 插件接口（on_access/on_log）不变，仅增加内部逻辑
