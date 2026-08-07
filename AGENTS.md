# VeryNginx v2 — Gotchas & Rules

> 记录项目开发过程中反复遇到的问题和修复方案，避免同一类 bug 重复出现。

## 目录

1. [Lua / OpenResty 坑](#1-lua--openresty-坑)
2. [路由调度](#2-路由调度)
3. [共享字典 (shared dict)](#3-共享字典-shared-dict)
4. [IP 声誉引擎](#4-ip-声誉引擎)
5. [GeoIP](#5-geoip)
6. [配置系统](#6-配置系统)
7. [插件与规则引擎](#7-插件与规则引擎)
8. [前端 Dashboard](#8-前端-dashboard)
9. [测试与 CI](#9-测试与-ci)
10. [安全](#10-安全)
11. [Firewall Helper (Go)](#11-firewall-helper-go)
12. [Kernel Blocking (Lua)](#12-kernel-blocking-lua)

---

## 1. Lua / OpenResty 坑

### 1.1 `pcall` 内不要 `ngx.exit`

`ngx.exit` 在 Lua 层面通过 error 实现，被 `pcall` 捕获后请求不会终止，后续代码继续执行。

**错误**：
```lua
pcall(function()
    ngx.exit(403)  -- 被 pcall 吞掉，请求继续
end)
```

**正确**：通过 `ctx.set_action` 设置响应，由 `rule_engine.apply()` 在 `pcall` 外部处理。

### 1.2 FFI 加载失败要用 `pcall` 保护

`ffi.load("libmaxminddb")` 在库不存在时直接崩溃，必须 `pcall`。

**正确**：
```lua
local ok, result = pcall(maxminddb.new, maxminddb, path)
if not ok then
    return false, "failed: " .. tostring(result)
end
_db = result
```

### 1.3 `lua_package_path` 必须在 `http {}` 上下文

`lua_package_path` / `lua_package_cpath` / `lua_code_cache` **不能在 main 上下文**（server 外部）声明，必须放在 `http {}` 块内。

### 1.4 `ngx.worker.id() == 0` 保护

任何定时器中的持久化操作必须只在 worker 0 执行，防止 N 个 worker 并发写同一文件。

**正确**：
```lua
local function persist_timer()
    if ngx.worker.id() ~= 0 then return end
    -- ... persist
end
```

### 1.5 `io.popen().close()` 返回值不可靠

在 OpenResty/LuaJIT 下，`io.popen().close()` 的 exit code 不可靠，不要用它判断命令执行结果。

**正确**：读取命令 stdout 判断，或使用 `os.execute` + 临时文件。

### 1.6 require 路径解析规则

Lua 模块查找顺序：`lua_package_path` 中列出的路径依次查找。调试时可以用 `package.searchpath("module.name")` 确认文件位置。

---

## 2. 路由调度

### 2.1 两阶段匹配（精确优先于参数化）

**经验教训**：单循环路由中，每个路由条目先检查精确匹配再退化到 `:id` 参数化匹配，但 `GET /waf/rules/pending` 会被 `GET /waf/rules/:id` 截获——因为循环遍历到 `:id` 条目时就匹配了，后面的精确路由条目永远不会被执行。

**正确**：使用两阶段匹配。

```lua
-- Pass 1: exact path match（顺序无关）
for _, route in ipairs(routes) do
    if method == route.method and path == route.path then
        return run_route(route)
    end
end

-- Pass 2: parameterized (:id) match
for _, route in ipairs(routes) do
    if method == route.method and route.path:find(":id") then
        -- ... match and run
    end
end
```

### 2.5 速率限制 key 必须用路由模式（`route.path`），而非实际 URI

API 中间件限速 bucket 若用实际请求路径（如 `/waf/rules/123`）构造 key，攻击者可通过改 `:id` 变出无限 bucket 绕过限速。必须用 `route.path`（路由模式 `/waf/rules/:id`）。

**正确**：
```lua
local rl_key = "api:" .. method .. ":" .. route.path .. ":" .. tostring(user)
```
> 认证分支（api/init.lua:87 附近）与非认证分支（按 IP）都如此。`route.path` 由 `_M.register` 存的是模式字符串。

### 2.2 `waf_rule_id` 通过 `ngx.ctx` 传递

参数化路由捕获的值放入 `ngx.ctx.waf_rule_id`，handler 通过它读取。不同 controller 不要共用该值。

### 2.3 Controller 注册契约

每个 controller 暴露 `_M.register(api)`，`api` 是 `api/init.lua` 的 `_M`。Controller 之间不互相依赖。新增 controller 时还必须在 `api/init.lua` 的 `CONTROLLERS` 表中注册。

### 2.4 API 中间件流水线

`run_route()` 按顺序处理所有跨切关注点：

1. **Auth** — `api.auth.middleware(ctx)`，未认证返回 401
2. **Rate limiting** — 认证路由 60 req/60s（按用户），未认证路由 20 req/60s（按 IP）；`/config` POST 额外限制 30 req/60s
3. **Idempotency-Key** — mutating 请求可携带 `Idempotency-Key` header，重复 key 返回 409（1 小时 TTL，基于 `vn_session`）
4. **Security headers** — 自动注入 `X-Content-Type-Options`/`X-Frame-Options`/`X-XSS-Protection`/`Content-Security-Policy`
5. **Response size limit** — 超过 10MB 截断为 413
6. **Audit log** — mutating 请求写入 `core.audit`

> **IP 输入验证统一用 `helpers.is_valid_ip()`**：API 层凡接收用户 IP（reputation score/clear、kernel_blocking promote/clear、frequency 规则 IP matcher）一律先过 `api/helpers.lua` 的统一校验（严格 IPv4 四段 0-255 + IPv6 单 `::`/8 组/4 位十六进制），不合法返回 400。不要用松散正则（如 `^[%d%.]+$` 会把 `999.1.1.1` 放进索引）。

---

## 3. 共享字典 (shared dict)

### 3.1 `get_keys(0)` 有 1024 条软限制

`ngx.shared.DICT:get_keys(0)` 最多返回 1024 个 key，且在大字典下性能差。

**正确**：维护一个独立的索引 key（如 `ip_rep:flagged_index`），只存储需要的 key。

```lua
-- 不要
local keys = shared:get_keys(0)

-- 要
local index_raw = shared:get("ip_rep:flagged_index")
local index = json.decode(index_raw)
for _, ip in ipairs(index) do
    -- ...
end
```

> **metrics dict 也要用索引**：`metrics.lua` 的 Prometheus 指标（尤其 per-rule gauge，每规则 3 个 key）超过 ~1024 个 key 时，`get_keys(1000)` 会丢尾。`metrics` 维护 `__metrics_index`（换行分隔的 key 列表），写路径在稀有「新 key」时才拿 `vn_locks` 的 `metrics:index_lock`（预算 500×2ms，与 kb 对齐；超时记 `ngx.WARN`，否则该指标在索引-only 导出下永久丢失）。`export_prometheus()` **只**以索引为准（不再 `get_keys` 并集兜底——get_keys 大字典性能差且有 1024 上限），并按 `{metrics, metrics_labeled}` 两个字典并集导出。注意 `parse_key`/导出重建 labels 用 `pairs()`，输出标签顺序不确定，测试勿按「第一个标签」断言。
>
> **高基数 per-instance 指标隔离到 `metrics_labeled`**：per-rule（`waf_rule_*`，每规则 3 个 key）与 per-IP（`ip_reputation_score`）属于 churn 频繁、无界增长的标签序列，统一字典会把它们继续挤占 core 计数器。`metrics.lua` 据指标名前缀路由：`^waf_rule_` 或 `==ip_reputation_score` 写入独立 `metrics_labeled`（16m）；其余留在 `metrics`（10m）。两个字典各自维护 `__metrics_index`，导出并集（`emit_dict` 按字典遍历）。`observability._collect_worker_stats` 的 dict 清单与 `in_http_block.conf` 已含 `metrics_labeled`。

### 3.2 用 `incr` 做原子计数器

不要 `get` → `decode` → 修改 → `encode` → `set`，这是非原子的。

**正确**：
```lua
-- 原子递增，不存在则从 0 开始，TTL 覆盖
shared:incr("counter:" .. key, 1, 0, ttl)
```

### 3.3 shared dict 名称硬编码

当前 shared dict 名称：`vn_config`、`vn_locks`、`vn_rate_limit`、`vn_session`、`ip_reputation`、`frequency_limit`、`healthcheck`、`statistics`、`metrics`、`metrics_labeled`、`dns_cache`。新增时要在 `nginx_conf/in_http_block.conf` 的 `lua_shared_dict` 中声明。

---

## 4. IP 声誉引擎

### 4.1 challenge 通过后 `clear_score` + `record_challenge_pass`

- `clear_score(ip)` — 清空所有信号槽
- `record_challenge_pass(ip)` — 递增连续通过计数，达到阈值后加入自动白名单

### 4.2 自动白名单

阈值与有效期定义在 `core/ip_reputation.lua` 的 `DEFAULTS.auto_whitelist`，`record_challenge_pass()` 读取 `config.ip_reputation.auto_whitelist`（不存在时回退 DEFAULTS）。

> **注意**：`config.lua` 的 schema **未声明** `ip_reputation.auto_whitelist` 字段。`normalize_defaults` 用 `deep_copy` 保留 config.json 中的未知字段，因此**完整配置可生效**——但 schema 不会填默认值、不做验证，**部分配置会静默失效**（如只写 `threshold` 则 `enabled` 为 nil → feature 被关闭）。如需安全可配，应在 schema 的 `ip_reputation` 字段中补上 `auto_whitelist` 子表以获得默认值填充和验证。

| 配置 | 默认 | 说明 |
|------|------|------|
| `threshold` | 3 | 连续通过 challenge 次数 |
| `ttl` | 3600s | 有效期 |
| `max_entries` | 1000 | 最大并发数 |

### 4.3 404 信号只针对 challenge 触发的 IP

不要给无 pending 状态的 IP 累加 404 信号，否则正常用户可能被误判。

### 4.4 信号配置

```lua
signals = {
    waf_challenge = 3,     -- WAF 触发 challenge
    waf_block = 5,         -- WAF 触发 block
    not_found = 1,         -- 404 请求（仅 pending 状态时累加）
    challenge_fail = 5,    -- 未通过 challenge
}
```

### 4.5 CC enforce 自动就绪

`readiness.compute()` 返回 `effective.cc.auto_ready`，当以下条件全部满足时为 `true`：
- 全局 `mode == "enforce"` + `cc.enabled == true` + `rule_ids` 非空
- Frequency migration 完成 + v2 counter namespace cutover
- Helper 健康 + topology = direct
- **但** `cc.enforce_ready` 仍为 `false`

Dashboard 检测到 `auto_ready` 后显示蓝色横幅 + 一键 "Enable CC enforce" 按钮，PATCH `cc.enforce_ready=true`。

### 4.6 Pending 索引热路径无锁快路径

`add_to_pending_index` 对**已存在**的 pending IP（其 per-IP key `ip_rep:pi:<ip>` 存活）直接 `set` 刷新 TTL 即返回，不再拿全局 `ip_rep:index_lock`（RMW + `ngx.sleep(0.001)` 自旋锁，高负载下是热点）。只有「全新 pending IP」才进锁做索引追加；去重由 `json_index_add_unlocked` 仍兜底。快路径安全的前提是不变量：live per-IP key ⇔ live 索引条目（删除/compact 都按 per-IP key 判活）。`remove_from_pending_index` 也一样：per-IP key 已不存在就直接返回，不拿锁（残留列表条目由 compact 清，扫描时读作 dead）。

---

## 5. GeoIP

### 5.1 数据库文件存在 ≠ GeoIP 可用

数据库文件 `.mmdb` 在磁盘上不等于能查询，`lua-resty-maxminddb` 模块必须加载成功。`is_available()` 检查 `_db ~= nil` 而不是文件是否存在。

### 5.2 启动后下载的数据库要自动重载

`lookup()` 和 `is_available()` 中检测到 `_db == nil` 时自动调用 `reload()`。

### 5.3 数据源：P3TERX GeoLite2-City

使用官方 MaxMind GeoLite2-City 数据库（~66MB），通过 P3TERX 镜像下载。

### 5.4 GeoIP 自动更新

`core/geoip_updater.lua` 在 `init_worker` 启动定时器，按配置间隔检查并下载最新数据库。CDN 和官方源可切换。

---

## 6. 配置系统

### 6.1 Schema 默认值保证 `plugin` 永远是 table

`config.lua` 的 schema 指定了 `plugin = { type = "table", default = {} }`，所以 `config.plugin` 永远是 table，**任何 nil 检查都是死代码**。

### 6.2 Webhook URL 验证

两层防护：
1. `validate_config()` 在保存时拒绝非 `https` 或私有 IP 的 URL
2. `send_webhook()` 在发送前再次验证

### 6.3 Config 热加载

`config.load_from_file()` 在 `init_by_lua` 阶段调用，运行时通过 `config.save()` 写入磁盘并更新 `config_data`。

### 6.4 `config.report()` 返回 JSON 字符串

`report()` 返回 JSON 而非 table。需要 table 时先 `json.decode(config.report())`。

### 6.5 `MODULE_ROOT` 自动检测

`config.lua` 和 `init.lua` 通过 `debug.getinfo(1, "S").source:match("^@(.+)/core/")` 自动检测安装前缀，无需 `VN_PREFIX` 环境变量。模块路径基于此解析。

### 6.6 频率限制规则模板库

`core/frequency_templates.lua` 提供 8 个预置场景模板，用户可通过 Dashboard 一键应用：

| 模板 | 场景 | 默认参数 |
|------|------|---------|
| `login_bruteforce` | 登录爆破防护 | limit=5, window=60s, block, path=/login |
| `api_abuse` | API 滥用 | limit=60, window=60s, block, path=/api/ |
| `crawler` | 爬虫/扫描 | limit=30, window=60s, challenge |
| `global_cc` | 全局 CC 防护 | limit=300, window=60s, challenge |
| `sensitive_api` | 敏感接口 | limit=10, window=60s, block, path=/reset-password |
| `per_user` | 按用户限速 | key=user, limit=100, window=60s |
| `host_based` | 按域名限速 | key=host, limit=120, window=60s |
| `aggressive_block` | 严格拦截 | limit=3, window=60s, code=403 |

- 端点：`GET /frequency/templates`（列表）、`GET /frequency/templates/:id`（预览）、`POST /frequency/templates/:id`（应用）
- `apply(name, overrides?)` 返回 rule table，deep-copy 模板，去重避免重复插入
- Dashboard：模板画廊卡片 → 预览弹窗（可调参数） → Apply → 保存为正式规则

### 6.7 Shared Dict 使用率告警

`core/alerting.lua` 第 5 种告警类型 `shared_dict_high_usage`：

| 配置 | 默认 | 说明 |
|------|------|------|
| `shared_dict_alert_threshold` | 80 | 触发告警的使用率百分比（10-99） |
| 监控范围 | 全部 11 个 dict | vn_config/vn_locks/vn_rate_limit/vn_session/statistics/metrics/metrics_labeled/healthcheck/dns_cache/frequency_limit/ip_reputation |
| cooldown | 2x window | 避免重复告警 |

使用率指标 `shared_dict_usage_pct` 同时通过 Prometheus `/metrics` 暴露（来自 `observability.lua`）。

### 6.8 新增 config section

```lua
waf_recommender = { type = "table", default = {
    enabled = true,
    min_hits = 10,           -- 最少命中次数才生成建议
    window_size = 3600,      -- 分析窗口（秒）
    min_patterns = 3,        -- 同 IP 最少不同 URI 模式怀疑为扫描
}}

auto_whitelist = { type = "table", default = {
    enabled = true,
    threshold = 3,           -- 连续通过 challenge 次数
    ttl = 3600,              -- 有效期（秒）
    max_entries = 1000,      -- 最大并发数
}}
```

> **注意**：上面的 `auto_whitelist` 示例仅为字段形状说明。`config.lua` 的 schema 当前**未声明** `ip_reputation.auto_whitelist`——config.json 中写全字段可生效（`normalize_defaults` 的 `deep_copy` 会保留未知字段），但无默认值填充、无验证，部分配置会静默失效。目前未配置时实际生效值来自 `core/ip_reputation.lua` 的 `DEFAULTS.auto_whitelist`。

---

## 7. 插件与规则引擎

### 7.1 两阶段规则评估

```
阶段一: 执行所有 hard block 规则（SQLi/RCE/路径穿越等）
前置-2: 检查 JS Challenge cookie（如果有效 → 跳过 challenge 规则）
阶段二: 执行 challenge 类规则
```

**原则**：硬 block 规则**总是执行**，cookie 只跳过 challenge 类规则。

### 7.1b 规则缓存版本检查必须用「已提交」版本键

`plugin/filter/init.lua` 的 `get_cached_rules()` 轻量快路径读 `waf_rules_version`（`save_rules` 在 chunk 缓存 + meta **全部写完之后**才设置），而非 `waf_rules_save_version`（`save_rules` 一开头就 `incr`）。若读后者，save 过程中 worker 会拿旧 chunk 重载并缓存到「新版本」下 → 陈旧规则集被永久缓存直到下次 save。用已提交键保证：版本翻新 ⟹ 底层 chunks/meta 一定已一致。

### 7.2 Challenge 作为 terminal action

- `RESULT` 表中包含 `CHALLENGE`
- `TERMINAL_ACTIONS` 包含 `challenge = true`
- 通过 `rule_engine.apply()` 执行，在 `pcall` 外部

### 7.3 JS Challenge Cookie

- **不能**用 `Set-Cookie` header 设置（否则直接设置 cookie 就绕过了 JS 执行验证）
- 通过 JavaScript 执行后由浏览器设置
- Cookie `Max-Age = 600`（与 `pending_ttl` 一致）
- `sign()` 不包含 `time_slot`，IP+UA 绑定 + 600s TTL 足够

### 7.4 插件优先级

| 插件 | 优先级 | 说明 |
|------|--------|------|
| filter | 100 | WAF 规则引擎 |
| frequency_limit | 200 | 频率限制 |
| browser_verify | 300 | JS Challenge |
| router | 400 | 管理路径路由 |
| proxy_pass | 500 | 反向代理 |
| static_file | 600 | 静态文件 |
| summary | 900 | 请求统计 |

### 7.5 WAF 规则推荐引擎

`core/waf_recommender.lua` 分析被阻断的流量（来自 `waf_recent_hits:data:` 环形缓冲区），自动识别攻击模式并生成规则建议。

- 分析触发：`POST /waf/recommendations/analyze`（手动）或 `init_worker` 定时器
- URI 归一化：UUID/十六进制/数字 → 占位符，合并同类模式
- 分类：path_traversal / rce / sqli / scanner（基于关键词匹配）
- 存储：建议写入 `vn_config` shared dict（7 天 TTL），通过 INDEX_KEY 索引
- 应用：`apply(id)` 调用 `waf-rule-manager` 创建正式规则并 reload
- Index 更新使用 `shared:add()` spin-lock 保证原子性（TOCTOU-safe），`add()` 内置去重

---

## 8. 前端 Dashboard

### 8.1 Vue 3 SPA (CDN, 无构建)

- 单文件 `dashboard/index.html`，包含 HTML 模板 + `<script setup>` + CSS
- Vue 3 通过 CDN (`https://unpkg.com/vue@3/dist/vue.global.prod.js`) 加载，无构建步骤
- 使用 Vue 3 Composition API（`ref`/`reactive`/`computed`）
- API 调用通过 `api(method, path, body?)` 函数

### 8.2 mount API

Dashboard 挂载方式：
```javascript
const app = Vue.createApp({
    setup() { /* ... */ }
}).mount('#app');
```

### 8.3 路由与 WAF Tab

WAF 面板的子页签切换通过 `wafTab` ref 控制。新增 tab 时：
1. 添加 tab 链接 `<a @click="wafTab='xxx'">`
2. 添加 `div v-if="wafTab==='xxx'"` 内容
3. 在 `loadWafData()` 中加入 `if (wafTab.value === 'xxx') await loadXxx()`

---

## 9. 测试与 CI

### 9.1 GitHub Actions

```
lint → unit-tests → integration-tests → performance-baseline
```

### 9.2 Docker Compose 启动失败

如果 OpenResty 配置错误导致容器启动失败，CI 目前会自动抓取日志：
```yaml
docker compose up -d --wait || (docker compose logs verynginx 2>&1 && exit 1)
```

### 9.3 测试脚本位置与运行方式

- 单元测试：`test/v2/phase0/*.spec.lua`（_kernel_blocking 相关的 phase0 集成测试）
- 遗留单元测试：`test/v2/spec/*.spec.lua`（_v1 模块，部分已迁移至 phase0）
- 集成测试：`test/v2/test_integration.py`
- Docker Compose：`test/v2/docker-compose.yml`

**运行命令（分两套，勿混用）**：

```bash
# spec 套件：必须带 spec_helper（CI 的 unit-tests job 用这条）
busted --helper=test/v2/spec/spec_helper.lua --lpath='./verynginx/?.lua;./verynginx/lua_script/?.lua;./verynginx/lua_script/module/?.lua' test/v2/spec/

# phase0 套件：必须【不带】--helper（自包含 ngx stub，加载真实模块）
busted --lpath='./verynginx/?.lua;./verynginx/lua_script/?.lua;./verynginx/lua_script/module/?.lua' test/v2/phase0/
```

> **⚠️ 勿用 `--helper=spec_helper.lua` 跑 phase0**：`spec_helper.lua` 注册了
> `package.preload["core.config"]`（进程级拦截 `require "core.config"`），会用一个
> 精简的 config stub 顶替真实模块。phase0 各 spec 是自包含的（自带 `ensure_ngx()`
> stub、加载真实 `core.config`），一旦带 helper 运行，`config.validate_config`、
> `config.save`、`config.atomic_mutate` 等全部命中 stub，导致 config_cross_field、
> config_password_redaction、config_whitelist_publish、frequency_rule_id_migration、
> random 等多文件「集体误报失败」。这些失败是跑错的产物，不是 bug。
> phase0 中真实存在的唯一历史 bug 曾在 `ipc_spec.lua`：mock socket 用了
> `settimeouts`/`receiveany` 而 `ipc_client.lua` 用的是真实 API
> `settimeout`（单数）/`receive(n)` —— 已修复，mock 现改为字节流 `receive(n)`。
> CI 只跑 spec 套件（带 helper），phase0 需在本地单独运行。

### 9.4 单元测试覆盖（phase0）

| Spec 文件 | 覆盖范围 |
|-----------|----------|
| `config_cross_field_spec.lua` | 配置跨字段验证、enforce 门槛校验 |
| `config_recursive_schema_spec.lua` | 递归 schema 默认值归一化 |
| `config_whitelist_publish_spec.lua` | 白名单 generation 发布路径 |
| `evidence_spec.lua` | scanner/CC 证据采集、slot 边界 |
| `executor_spec.lua` | Nft Executor contract 测试 |
| `frequency_rule_id_migration_spec.lua` | Frequency Rule ID m1 迁移算法 |
| `frequency_templates_spec.lua` | 频率限制规则模板库 |
| `frequency_v2_namespace_spec.lua` | v2 counter namespace 冷切换 |
| `ipc_spec.lua` | IPC Protocol v1 framing/envelope |
| `kernel_blocking_controller_spec.lua` | API 控制器 10 个端点 |
| `lifecycle_readiness_spec.lua` | 生命周期、generation 转换、功能标志就绪检查 |
| `promotion_enforce_spec.lua` | scanner/CC enforce 晋升、require_challenge_fail |
| `promotion_state_machine_spec.lua` | 状态机转换、list/compact |
| `reconcile_chunked_spec.lua` | 分块 reconcile、final_chunk gating |
| `reconciliation_spec.lua` | 全量 reconcile、scope rebind |
| `scope_binding_spec.lua` | Protected Scope Binding、scope_digest |
| `ttl_ladder_spec.lua` | TTL 阶梯续期 |
| `waf_recommender_spec.lua` | WAF 推荐引擎 index 原子性 |
| `whitelist_generation_spec.lua` | 白名单 epoch/sequence 缓存 |
| `bucket_history_diff_spec.lua` | bucket-history / diff 端点 |
| `shared_dict_alert_spec.lua` | shared dict 使用率告警 |

---

## 10. 安全

### 10.1 CSRF

每个用户 session 关联一个 CSRF token，通过 `GET /csrf` 获取，变更请求需在 header 中携带。

### 10.2 密码哈希

- 内置：`PBKDF2-HMAC-SHA256`
- 可选升级：`bcrypt` / `argon2`

### 10.3 Session 管理

- `HMAC-SHA256` 签名
- 服务端可撤销（`session.revoke(token)`）
- 密钥支持轮转

### 10.4 安全头

所有 API 响应包含：
```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; script-src 'self'; ...
```

### 10.5 速率限制

- 认证路由：60 req/60s（按用户）
- 未认证路由：20 req/60s（按 IP）
- `/config` POST：额外 30 req/60s

### 10.6 幂等性

mutating 请求可携带 `Idempotency-Key` header，重复 key 返回 409（1 小时 TTL，基于 `vn_session`）。

> **只在成功后固化 idempotency key**：`run_route` 先以 `"processing"` 占位去重并发重复请求；handler 成功（非 5xx）才置最终 key，异常/5xx 时 `delete` 释放，允许重试——否则一次 5xx 会烧掉整小时的重试窗口。
>
> **claim 必须原子**：判重 + 占位不能是 `get()`+`set()` 两步（多 worker 同 key 并发可都读到 nil 都执行）。用 `s:add(cache_key, "processing", 3600)` 原子 claim，add 返回 false 者直接 409。
>
> **413 视为释放**：响应 >10MB 截断为 413 属失败。幂等固化逻辑必须放在响应大小检查**之后**，且 `status == 413` 与 5xx 一并 `delete` 释放，否则客户端拿不到完整数据却要在 1 小时内被 409 挡着重试。

### 10.7 响应大小限制

API 响应超过 10MB 截断为 413。

### 10.8 SSRF 防护

所有 webhook URL 必须：
- 以 `https://` 开头
- 不指向私有 IP 段（`127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`）

> **域名 webhook 也要 DNS 解析校验**：仅字面匹配 host 段可被 DNS 重绑定绕过（字面是公网域名、实际解析到内网 IP）。`alerting.lua` 的 `validate_webhook_url` 在 host 为域名时经 `resty.dns.resolver` 解析 A/AAAA，任一解析结果为私有地址即拒绝；解析器不可用时走 best-effort（仅字面检查）。`config.lua` 保存时校验保留字面检查。
>
> **`::ffff:` IPv4-mapped IPv6 会绕过 IPv4 私有段判定**：`https://[::ffff:10.0.0.1]/` 的 host 是 IPv6 字形，若只按 IPv4 pattern（`^10%.` 等）匹配会漏判为公网。`is_private_ip` 需先剥离 `^::ffff:` 前缀、对方括号内是点分十进制时递归走 IPv4 判定。SSRF 校验时此类字形同样视为私有并拒绝。

### 10.9 GeoIP 目录权限

GeoIP 数据库目录**禁止 777**。`install-lnmp.sh` 已设置 755 + chown nginx_user，因此：
- `geoip.lua` 的 `mkdir` 应使用 `-m 755`（非 777）
- `geoip_updater.lua` 的 `ensure_dir` 不应 `chmod 777`
- 下载的 `.mmdb` 文件应 `chmod 644`（owner rw, others r）
- 目录写权限通过 ownership（nginx user）实现，不依赖 world-writable

### 10.10 core/random PRNG 种子

`math.random` **禁止**未播种直接使用（每次进程启动产生相同序列，影响 CSRF token、session ID、密码 salt）。`core/random.lua` 的 `seed_prng()` 在首次 `math.random` 回退前自动播种（熵源：PID + worker_id + ngx.now + os.clock 经 XOR 混合）。即使在 `ngx.random_bytes` 和 `/dev/urandom` 均不可用的极端环境下，也不会产生可预测输出。

---

## 11. Firewall Helper (Go)

### 11.1 概述

Go 实现的特权 Helper 进程，监听 Unix Domain Socket (`/run/verynginx/firewall-helper.sock`)，接收 VeryNginx worker 发来的 Protocol v1 帧并转换为 nftables 操作。

### 11.2 架构

```
VeryNginx worker (Lua)
    ↓ Unix socket (Protocol v1: 4-byte BE length + JSON)
helper/main.go
    ↓ exec.Command("/usr/sbin/nft", "-f", "-")
nftables (Linux kernelnetfilter)
```

### 11.3 关键设计

| 项目 | 说明 |
|------|------|
| 语言 | Go 1.21+，静态二进制无运行时依赖 |
| 权限 | 仅需 `CAP_NET_ADMIN`，不需要 root |
| Socket | systemd socket-activated |
| 故障安全 | nft 执行失败返回 `{ok:false, error}`，不 panic |
| 原子性 | nft `-f -` 整批写入（单个事务） |
| In-memory state | 同时在内存中维护，用于 health/list 快速响应 |

### 11.4 文件结构

```
helper/
├── go.mod
├── main.go              ← 全部逻辑 (~450 行)
├── main_test.go         ← e2e 测试 (需 E2E=1 + CAP_NET_ADMIN)
├── firewall-helper.socket ← systemd socket unit
└── firewall-helper.service ← systemd service unit
```

### 11.5 部署

```bash
# 构建
cd helper && go build -o firewall-helper .

# 安装二进制
cp firewall-helper /usr/local/bin/

# systemd units
cp firewall-helper.{socket,service} /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now firewall-helper.socket
# service 在首次连接时自动启动 (socket-activated)
```

### 11.6 测试

```bash
# 单元 + e2e (需要 CAP_NET_ADMIN)
cd helper && E2E=1 go test -v

# Lua client → Go Helper → nftables 全链路
bash test/v2/phase0/test_go_helper_e2e.sh
```

### 11.7 协议兼容性

- Protocol v1 帧: 4-byte big-endian length + JSON envelope
- 9 种操作: probe, health, ensure_base, add, delete, list, replace_allow_snapshot, reconcile, flush_owned
- 环境变量 `VN_HELPER_SOCKET` 可覆盖 socket 路径（用于测试）

### 11.8 reconcile 必须镜像 Add 的独立防御

`Add` 在写 nft 前会执行三道独立防御：`isReservedOrSpecialIP`（拒环回/组播/未指定等）、`isAllowCoveredLocked`（拒 allow 覆盖的 drop）、容量与 DROP 速率限制。`reconcileFull` / `reconcileChunked` 是批量路径，**同样必须执行这些检查**，否则：

- 绕过 reserved-IP 检查 → 可能把 `127.0.0.1` 等地址打入 drop 集合（H2）。
- 绕过 allow-cover 检查 → allow 保护的 IP 仍被 drop。
- 不更新 `b.allowEntries` → 后续 `Add` 的 `isAllowCoveredLocked` 因 map 陈旧而失效（H1）。

实现要点：
- 遍历 snapshot 时，`Set == "allow"` 的条目累加到局部 `batchAllow` map，并在写状态后同步 `b.allowEntries[ip] = true`。
- drop 条目：reserved 或 `allowCoveredLocked(ip, batchAllow)` 命中则跳过（计入 `failed`），不进入 nft 命令也不写 `b.state`。
- `batchAllow` 让同 snapshot 内先出现的 allow 能保护后出现的 drop（chunked 模式下跨 chunk 的保护由已提交的 `b.allowEntries` 覆盖）。

> 回归测试见 `helper/reconcile_guards_test.go`（无需 E2E，直接构造 `NFTBackend` + `VN_HELPER_SKIP_NFT=1`）。

### 11.9 连接必须设 deadline（防慢客户端 goroutine 泄漏）

`handleConnection` 的 read/write 循环若无 deadline，慢客户端（slow-loris）或断网未关的 socket 会永久阻塞其 goroutine；堆积的 stuck reader 还会拖慢等待 backend mutex 的合法 worker。

- 每请求顶部刷新 `conn.SetDeadline(time.Now().Add(connIdleTimeout))`（默认 30s）。
- 超时后 `readFrame` 返回 `i/o timeout`，连接关闭、goroutine 退出。
- `connIdleTimeout` 为 package-level `var`（非 const），测试可覆盖为短值验证。

> 回归测试见 `helper/conn_deadline_test.go`（覆盖 `connIdleTimeout` 至 300ms，验证停滞连接在超时后被关闭）。

### 12.1 模块文件结构

```
verynginx/core/kernel_blocking/
├── init.lua               ← 主入口：status/persist/restore/diff/bucket-history
├── promotion.lua          ← Scanner/CC Promotion Policy
├── state_machine.lua      ← 候选/期望状态生命周期（10 态）
├── desired_state.lua      ← 期望状态持久化（基于 generation）
├── token_bucket.lua       ← 自动晋升令牌桶（microunits 精度）
├── whitelist_generation.lua ← 白名单 epoch/sequence 缓存
├── evidence.lua           ← scanner/CC 证据采集
├── readiness.lua          ← 功能标志/引用完整性检查
├── lifecycle.lua          ← worker 0 调度器 wiring
├── reconciliation.lua     ← 分块 reconcile 调度
├── snapshot.lua           ← snapshot 分块（chunked reconcile）
├── scope_binding.lua      ← Protected Scope Binding
├── ttl_ladder.lua         ← TTL 阶梯式续期
├── executor_contract.lua  ← Executor 接口契约
├── executor_ipc.lua       ← IPC Executor 包装（含 rebind）
├── executor_mock.lua      ← Mock Executor（测试用）
├── executor.lua           ← Executor 工厂
├── ipc_client.lua         ← Unix Socket 客户端（含 backoff）
├── ipc_protocol.lua       ← Protocol v1 编解码
└── ip_encoding.lua        ← IPv6 规范化（RFC 5952）
```

### 12.2 关键经验教训

- **Add 操作必须 3 阶段提交**：先 nft 成功 → 再更新 in-memory state。之前先更新内存再执行 nft，失败后状态漂移。- **candidate/desired 索引追加必须在 index 锁内做 RMW**：`state_machine.upsert` 曾直接在锁外 get→decode→append→set `INDEX_KEY`，多 worker 并发首插同一复合键会重复追加（配合 `INDEX_TTL` 看似收敛，实际索引无界增长）。现经 `index_add_under_lock`（锁 `kb:candidate_index_lock` 于 vn_locks）原子追加。
- **索引锁超时不得静默失败**：`desired_state.index_add` / `state_machine.index_add_under_lock` 曾 `retries>100 直接 return`，条目已写而索引未记 → reconcile 无法发现（悬空条目）。现改为：更宽松预算（500×2ms）+ 超时记 `ngx.ERR` 并返回 false；调用方 `set_desired`/`upsert` 收到 false 后**回滚已写条目并上抛错误**，绝不留下有条目无索引的记录（悬空对 reconcile 永远不可见）。
- **`remove` 的 index 删除必须持锁**：`state_machine.remove` 曾直接 `s:get(INDEX)` → filter → `s:set(INDEX)` 不持锁，与持锁的 `index_add_under_lock` 并发时，后者新追加的索引条目会被 `remove` 的陈旧 `index_write` 覆盖 → 新条目成孤儿（有数据无索引）。现经 `index_remove_under_lock` 持锁删除。
- **`compact_index` 定期清理候选索引**：candidate index 只追加不删除，必须每 300 秒扫描并移除过期条目。
- **索引锁必须带 token 校验释放**：`desired_state.index_add/index_remove/compact_index_if_due` 与 `state_machine.index_add_under_lock/compact_index` 均用 `random.bytes(8)` token 做 `l:add`，释放前 `l:get == token` 才 `delete`。不要用 worker id 直接 `l:delete`——锁 TTL 超时被他人抢走后，旧持有者的 unlock 会误删他人锁。
- **desired index 的 compact 需在 count 路径也触发**：`index_write` 用 TTL 0（永不过期，条目本身可能无限 TTL，index 必须活得更久），死条目只能靠 compact 清理；`count_desired`/`count_by_list` 与 `list_desired` 一样要先 `compact_index_if_due()`，否则长期只调 count 时 index 残留死条目。
- **`clear_auto` 的 index 读改写必须持锁**：`clear_auto` 曾直接 `index_read` → 循环 → `index_write` 不持锁，与持锁的 `set_desired`/`index_add` 并发时，后者新追加的索引条目会被 `clear_auto` 的 `index_write(kept)` 覆盖 → 新条目成孤儿（有数据无索引，reconcile 永远不可见）。现用 `index_lock`/`index_unlock` 包裹整个读改写，与其他索引操作串行。
- **`is_private_ip` 的 IPv6 链路本地范围判定**：link-local 是 `fe80::/10`，前 10 位固定为 `1111111010`，即第 3 个 hex 字符为 `8/9/a/b`、第 4 个字符可为任意 hex。曾误用 `^fe[89ab]:`（要求第 4 字符为 `:`），导致 `fe80::1` 漏判。现为 `^fe[89ab][0-9a-f]:`。
- **webhook URL 的 IPv6 括号字面量必须剥离后校验**：`https://[::1]/hook` 的 host 提取后经 `host:match("^([^:]+)")` 会截成 `[`，绕过私网检查（SSRF）。须先识别 `^[...]` 括号字面量，提取内部 IPv6 地址直接用 `is_private_ip` 判定。`alerting.lua` 与 `config.lua` 两处校验均已修复。
- **API promote 需独立安全检查**：controller `handle_promote()` 自身做 IP 格式/保留地址/白名单/capacity 校验，不能依赖 executor。
- **CC require_challenge_fail 阻止了大部分 NAT 误封**：同一 IP 必须同时满足 `min_violation_windows` 且存在 challenge_fail 证据。
- **close_socket 只在 had_socket 时 invalidate scope binding**：首次建连前 close 不应 invalidate，避免不必要的 rebind。
- **evidence slot 索引可能为负**：`slot - i` 在跨窗口边界时可能为负，必须 break 而非继续。
- **mock 的 reconcile 闭包陷阱**：`idx[key]` 必须在 `add()` 之前捕获（`key_in_idx = idx[key]`），否则 add 会修改 idx 导致判定错误。
- **mock `flush_owned` 区分 scope**：`auto` 只删 scanner_drop + cc_drop，`all`/`detach` 才包含 manual_drop。
- **mock `reconcile` expires_at→ttl 转换**：使用 `math.max(expires_at - now, 1)`，不允许负 TTL。
- **dispatch_pending 也必须持久化**：promotion 在 `dispatch_pending` 时**尚未**写 desired（desired 在 executor.add 成功后写）。dispatch 窗口内崩溃，SM 条目既不持久化（persist 原本只滤 `installed`）、也不在 desired → 重启后丢失封禁意图，且 kernel 若已下发则成孤儿。修复：dispatch_pending upsert 带上 `expires_at = plan.expires_at`，persist 防御性扫描从单一 `installed` 状态扩展为 `{installed, dispatch_pending}` 两趟。
- **错误消息串接要逐字段校验**：Go 端三级 Path 未取其值就拼 message 属于明显错误，但更广的教训是——在打印/校验前应先用 `strings.Contains` 等字段级检查，勿先拼字符串再误判“正常”。（被误报告为缺陷，实为历史遗留，#6/#11/#19 为真缺陷。）
- **list 分页大小可配置，reconcile 用大页**：Go `List` 支持 payload 可选 `page_size`（默认 100，上限 4096，1 MiB 帧预算内 ~256KB JSON）；`executor_ipc.list` 透传该参数。`reconciliation.collect_actual` 用 `kb_cfg.reconcile_list_page_size`（默认 1000）——100k 条目从 1000+ 次 IPC 降到 ~100 次。mock 执行器默认 1000 与 Go 默认不一致，属预期（各自用各自默认）。schema 已声明 `reconcile_list_page_size`/`reconcile_chunk_size`（`kernel_ip_blocking` 是 `reject_unknown=true`，不声明会拒配）。

### 12.3 API 控制器端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/kernel-blocking/status` | 配置/模式/健康/统计/桶状态 |
| GET | `/kernel-blocking/entries` | 分页查询期望+实际条目 |
| GET | `/kernel-blocking/candidates` | 分页查询候选 |
| POST | `/kernel-blocking/promote` | 手动封禁 |
| POST | `/kernel-blocking/clear` | 手动解除 |
| POST | `/kernel-blocking/pause` | 紧急暂停 |
| POST | `/kernel-blocking/flush-auto` | 清理自动集合 |
| POST | `/kernel-blocking/reconcile` | 手动触发同步 |
| GET | `/kernel-blocking/bucket-history` | 令牌桶余额历史 |
| GET | `/kernel-blocking/diff` | 期望 vs 实际差异 |

### 12.4 Docker 构建

Dockerfile 必须安装 Go 1.21+（官方 tar.gz），不能依赖 Debian Bullseye 的 `golang-go` 包（Go 1.15）。`//go:build` 语法要求 Go 1.17+，且 `go.mod` 声明 `go 1.21`。

---

## 附录：模块文件结构
verynginx/
├── AGENTS.md                ← 本文档 — 开发经验与约束
├── Dockerfile               ← 生产镜像 (debian:bullseye-slim + install.py)
├── install-lnmp.sh          ← 一键安装脚本 (LNMP 环境)
├── verynginx/
│   ├── on_rewrite.lua       ← 请求重写阶段处理
│   ├── on_access.lua        ← 请求访问阶段处理
│   ├── on_log.lua           ← 请求日志阶段处理
│   ├── waf-rule-manager.lua ← WAF 规则引擎 (CRUD/版本/测试)
│   ├── api/
│   │   ├── init.lua         ← 路由调度 + 中间件
│   │   ├── helpers.lua      ← 共享工具函数
│   │   ├── controllers/
│   │   │   ├── auth.lua     ← 登录/登出
│   │   │   ├── config.lua   ← 配置/状态/审计
│   │   │   ├── waf_rules.lua ← WAF 规则 CRUD
│   │   │   ├── waf_stats.lua ← WAF 统计/命中/时间线
│   │   │   ├── waf_recommender.lua ← 规则推荐
│   │   │   ├── reputation.lua ← IP 声誉
│   │   │   ├── geoip.lua    ← GeoIP 查询/配置
│   │   │   ├── fingerprint.lua ← TLS 指纹
│   │   │   ├── frequency.lua ← 频率限制 + 模板库
│   │   │   └── plugins.lua  ← 插件管理/上游健康
│   │   ├── auth.lua         ← 认证 middleware
│   │   ├── csrf.lua
│   │   └── rate_limit.lua
│   ├── core/
│   │   ├── init.lua, config.lua, plugin.lua, rule_engine.lua
│   │   ├── ip_reputation.lua, statistics.lua, session.lua
│   │   ├── geoip.lua, geoip_updater.lua, alerting.lua
│   │   ├── ja3.lua, fingerprint_db.lua
│   │   ├── metrics.lua, observability.lua
│   │   ├── audit.lua, context.lua, hmac.lua
│   │   ├── password_hash.lua, random.lua
│   │   ├── waf_recommender.lua
│   │   └── frequency_templates.lua
│   ├── core/kernel_blocking/ ← 内核层 IP 封禁 (§12)
│   ├── plugin/
│   │   ├── filter/          ← WAF + IP 声誉 + GeoIP
│   │   ├── browser_verify/  ← JS Challenge + Cookie
│   │   ├── frequency_limit/
│   │   ├── proxy_pass/
│   │   ├── router/
│   │   ├── static_file/
│   │   └── summary/
│   ├── dashboard/index.html ← Vue 3 SPA
│   ├── nginx_conf/
│   │   ├── in_http_block.conf ← shared dict, lua_package_path
│   │   ├── in_external.conf   ← upstream, main context
│   │   └── in_server_block.conf
│   ├── configs/
│   │   ├── config.default.json ← 默认配置模板
│   │   └── config.json         ← 运行时配置 (CI 生成)
│   └── resty/
│       └── maxminddb.lua    ← vendored lua-resty-maxminddb
└── helper/
    ├── go.mod
    ├── main.go              ← Protocol v1 server + nftables executor
    ├── main_test.go         ← e2e 测试 (E2E=1)
    ├── firewall-helper.socket ← systemd socket activation
    └── firewall-helper.service ← systemd service unit

test/
└── v2/
    ├── spec/            ← 单元测试 (busted)
    ├── phase0/          ← Kernel blocking 集成测试
    ├── test_integration.py ← 集成测试 (Python/curl)
    └── docker-compose.yml  ← CI 测试环境
```