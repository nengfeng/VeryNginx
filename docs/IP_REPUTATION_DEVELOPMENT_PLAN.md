# IP 声誉评分引擎 + Challenge 机制 — 开发实施计划

> 配套设计文档：[IP_REPUTATION_AND_CHALLENGE.md](IP_REPUTATION_AND_CHALLENGE.md)
>
> 本文给出该方案的编码实施顺序。核心原则：每个阶段独立可编译、可测试，主请求路径的高风险改动集中且被安全测试守住，系统在任何阶段结束时都不处于"半破坏"状态。

---

## 总览

| 阶段 | 内容 | 风险 | 是否改动主请求路径 |
|------|------|------|----------------------|
| 阶段 0 | 基础设施（shared dict + config schema） | 极低 | 否 |
| 阶段 1 | 核心引擎 `ip_reputation.lua` + 单测 | 低（隔离） | 否 |
| 阶段 2 | Challenge 动作管线（rule_engine + plugin + apply） | 中 | 否（仅新增通路） |
| 阶段 3 | filter 接线（两阶段规则评估） | **高** | **是** |
| 阶段 4 | 采集点与初始化（summary + init） | 中 | 是（log 阶段） |
| 阶段 5 | 管理面（API + Dashboard + browser_verify 同步） | 低 | 否 |

---

## 阶段 0 — 基础设施（无行为变更，先打地基）

纯声明式改动，不影响任何现有请求流程，零风险先合入。

1. **`nginx_conf/in_http_block.conf`** — 新增 `lua_shared_dict ip_reputation 16m;`
   - 最先做，否则新模块拿不到 shared dict。
2. **`core/config.lua`** — schema 增加 `ip_reputation` 字段（含默认值，对齐设计文档六节的 JSON）
   - 让配置能被解析、有默认值兜底。

---

## 阶段 1 — 核心引擎（独立可测，不接线）

整个方案的心脏。此时引擎尚未被任何请求路径调用，可完全隔离地跑通单测，把评分/标记逻辑锁死后再接线。

3. **`core/ip_reputation.lua`（新建）** — 建议按内部依赖顺序实现：
   - 时间分槽读写基元 + `WEIGHTS` 表
     - **关键（S1）**：`ip_rep:waf:<ip>:<slot>` 存"累计分值"而非命中次数。`record_signal` 按信号权重 `shared:incr(key, WEIGHTS[sig], 0, window)` 累加，`get_score` 直接求和。
   - `increment_req` / `record_ua`（`shared:add` 去重 + `max_ua_distinct=20` 上限，防 unbounded key）
   - `record_signal` / `get_score`（含 `diversity_factor` 加权）
   - `set_pending` / `has_pending` / `clear_pending`
   - `flag_ip` / `is_flagged`（先查 `ip_rep:flagged:<ip>`，未命中则算分 → score ≥ threshold 时自动 `flag_ip` → 10s 结果缓存）/ `clear_ip` / `clear_score`
   - `is_whitelisted` / `add_whitelist` / `remove_whitelist`（**注意 CIDR 支持**）
   - `flagged_index` 维护 + `list_flagged` / `get_stats`（`flagged_today`）
   - `persist` / `restore`（`ngx.worker.id()==0` 保护，`tmp + rename` 原子写）
4. **`test/v2/spec/ip_reputation_spec.lua`（新增）** — 紧跟第 3 步：
   - 信号累加、`get_score` 加权、`diversity_factor`
   - `min_requests` 门槛
   - `flag_ip` / `is_flagged` 冷却期
   - 持久化 `persist` → `restore` 往返

---

## 阶段 2 — Challenge 动作管线（先通路，后触发）

先把"challenge 这个动作能被正确落地并中断插件链"这条通路建好并测通，再让 filter 去触发它。

5. **`core/rule_engine.lua`** — `RESULT` 增加 `CHALLENGE`；`apply()` 增加 challenge 分支
   - 位置：PROXY/STATIC 之后、ACCEPT 之前；负责调用 `challenge()` 并 `ngx.exit(200)`。
6. **`core/plugin.lua`** — `TERMINAL_ACTIONS` 增加 `challenge = true`
   - **⚠️ 必须与第 5 步同一批合入**，否则下游插件（proxy_pass 等）会覆盖 challenge 动作。
7. **`plugin/browser_verify/javascript_verify.lua`** — `challenge()` 移除内部 `ngx.exit(200)`（改由 `apply` 调用），`sign()` 保持不变
   - **⚠️ 高优先级安全项（见设计文档 8.1.1）**：反射进 challenge HTML 的 `uri`/`http_host`/`query_string` **必须做 JS 字符串转义**（或用 `dkjson.encode` 生成合法字面量），跳转目标做协议白名单，防反射型 XSS。此项与本步同批完成。
8. **`test/v2/spec/rule_engine_challenge_spec.lua`（新增）** + **`test/v2/spec/plugin_terminal_actions_spec.lua`（新增）** + **`test/v2/spec/security_challenge_xss_spec.lua`（新增）**
   - 验证 challenge 是 terminal action、`apply` 正确分发
   - **关键安全测试**：构造带 `"><script>` / `";alert(1)//` 的 uri/query，断言 challenge HTML 输出已转义、不产生可执行脚本（必须绿）

---

## 阶段 3 — filter 接线（核心行为变更，最高风险）

唯一改动主请求路径的一步，放在通路和引擎都测通之后，风险最可控。安全测试是硬门槛。

9. **`plugin/filter/rules.lua`** — `attack_code_leak` 改 `challenge`，其余保持 `block`
10. **`plugin/filter/init.lua`（重大修改）** — 重写为两阶段评估：
    - **⚠️ 保留现有模块级 require，重写时勿遗漏**（否则运行时 nil 错误）。当前文件已有：
      `local config = require "core.config"`、`local matcher = require "matcher.init"`、`local waf_manager = require "waf-rule-manager"`
      重写后新增：`local ip_reputation = require "core.ip_reputation"`、`local javascript_verify = require "plugin.browser_verify.javascript_verify"`
      （注：现有文件**不含** cjson / lua-resty-string；如实现中确需，按需在模块级新增，不要在函数体内 require）
    - 前置检查：前置-1（管理路径）→ 前置-0（req/ua 计数）→ 前置-1.5（白名单）→ 前置-3（is_flagged）
    - `split_rules` 分组
    - **阶段一**：硬 block 规则始终执行（不检查 cookie）
    - cookie 检查：有效 → `clear_score` + return
    - `has_pending` → `challenge_fail`（仅无 cookie 时）
    - **阶段二**：challenge 规则
    - **保留**：`load_rules().rules` 解包 + fallback、`check_rate_limit`、`record_hit`
11. **`test/v2/spec/filter_challenge_spec.lua`（新增）** + **`test/v2/spec/security_cookie_bypass_spec.lua`（新增）**
    - 正常用户流程、扫描器累计封禁流程、白名单流程
    - **关键安全测试**：持有效 cookie 仍无法绕过 SQLi/RCE/path traversal block（必须绿）

---

## 阶段 4 — 采集点与初始化

12. **`plugin/summary/init.lua`** — log 阶段采集 404
    - 模块级 require（非函数体内）
    - `javascript_verify.check` 有 cookie 则不计数 404
    - `reputation:challenge_response` 标记跳过 statistics 统计
13. **`core/init.lua`**
    - `init()` 调用 `ip_reputation.restore()`
    - `init_worker()` 在 `ngx.worker.id()==0` 起 **600s `ip_reputation.persist()` 定时器（仅此一个）**
    - **⚠️ 不要注册 30s flush 定时器**：`flush_hit_stats`/`persist_recent_hits` 属于 WAF 命中统计，已由 `waf_manager.init_worker()` 内部注册，重复注册会导致双倍执行
    - **唯一定时器注册点**，不要重复注册

---

## 阶段 5 — 管理面（不影响数据面）

14. **`api/init.lua`** — 增加 `/verynginx/api/reputation/*` 路由
    - stats / flagged / whitelist / score / clear / persist
    - 复用现有 auth + CSRF
15. **`plugin/browser_verify/init.lua`** + **`plugin/browser_verify/cookie_verify.lua`** — 同步改为 `set_action("challenge", { type = ... })`
    - **非阻塞项**（`default_enable = false`），可最后做
16. **`support/verify_javascript.html`** — cookie 改为 `Max-Age=600; SameSite=Strict`，移除硬编码 365 天持久化
17. **`dashboard/index.html`** — IP 声誉面板（已标记列表 + 手动管理 + 实时分数图）

---

## 关键顺序约束（不可违反）

1. **阶段 2 的第 5、6 步必须一起合入**（`apply` challenge 分支 + `TERMINAL_ACTIONS`），否则 challenge 动作会被下游插件覆盖，等同于从未存在。
2. **第 10 步（filter）依赖第 3 步（引擎）和阶段 2（通路）全部就绪**，不能提前。
3. **第 16 步（HTML `Max-Age=600`）与 `pending_ttl=600` 是一对**，只改一边会导致 cookie/pending 生命周期错位。
4. 每个阶段结束跑一次 `.luacheckrc` 静态检查 + 对应 spec，绿了再进下一阶段。

---

## 建议的合入分批

| PR | 覆盖阶段 | 特点 |
|----|----------|------|
| **PR1** | 阶段 0 + 1 | 基础设施 + 引擎 + 单测；零行为变更，安全合入 |
| **PR2** | 阶段 2 + 3 | challenge 通路 + filter 接线 + 安全测试；核心功能，重点评审 |
| **PR3** | 阶段 4 + 5 | 采集、初始化、API、Dashboard、browser_verify 同步；收尾 |

每个 PR 都能独立编译通过、独立测试。主路径的高风险改动集中在 PR2，且被 `security_cookie_bypass_spec.lua`（cookie 不绕过 block）和 `security_challenge_xss_spec.lua`（challenge HTML 无 XSS）两道安全测试守住。

---

## 验收清单（Definition of Done）

- [ ] `.luacheckrc` 全绿
- [ ] `test/v2/spec/ip_reputation_spec.lua` 通过
- [ ] `test/v2/spec/rule_engine_challenge_spec.lua` 通过
- [ ] `test/v2/spec/plugin_terminal_actions_spec.lua` 通过
- [ ] `test/v2/spec/security_challenge_xss_spec.lua` 通过（**安全硬门槛**）
- [ ] `test/v2/spec/filter_challenge_spec.lua` 通过
- [ ] `test/v2/spec/security_cookie_bypass_spec.lua` 通过（**安全硬门槛**）
- [ ] 正常浏览器访问触发 challenge → 自动通过 → 后续透明放行（手动验证）
- [ ] 无 JS 扫描器在约 4 次请求内被 flag，冷却期 600s（手动验证）
- [ ] 持 cookie 发送 SQLi payload 仍被 block 403（手动验证）
- [ ] nginx reload/重启后 flagged 列表从磁盘恢复（手动验证）
