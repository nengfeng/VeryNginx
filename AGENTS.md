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

### 2.2 `waf_rule_id` 通过 `ngx.ctx` 传递

参数化路由捕获的值放入 `ngx.ctx.waf_rule_id`，handler 通过它读取。不同 controller 不要共用该值。

### 2.3 Controller 注册契约

每个 controller 暴露 `_M.register(api)`，`api` 是 `api/init.lua` 的 `_M`。Controller 之间不互相依赖。新增 controller 时还必须在 `api/init.lua` 的 `CONTROLLERS` 表中注册。

### 2.4 API 中间件流水线

`run_route()` 按顺序处理所有跨切关注点：

1. **Auth** — `api.auth.middleware(ctx)`，未认证返回 401
2. **Rate limiting** — 认证路由 60 req/60s（按用户），未认证路由 20 req/60s（按 IP）；`/config` POST 额外限制 30 req/60s
3. **Idempotency-Key** — mutating 请求可携带 `Idempotency-Key` header，重复 key 返回 409（1 小时 TTL，基于 `vn_locks`）
4. **Security headers** — 自动注入 `X-Content-Type-Options`/`X-Frame-Options`/`X-XSS-Protection`/`Content-Security-Policy`
5. **Response size limit** — 超过 10MB 截断为 413
6. **Audit log** — mutating 请求写入 `core.audit`

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

### 3.2 用 `incr` 做原子计数器

不要 `get` → `decode` → 修改 → `encode` → `set`，这是非原子的。

**正确**：
```lua
-- 原子递增，不存在则从 0 开始，TTL 覆盖
shared:incr("counter:" .. key, 1, 0, ttl)
```

### 3.3 shared dict 名称硬编码

当前 shared dict 名称：`vn_config`、`vn_locks`、`ip_reputation`、`frequency_limit`、`healthcheck`、`statistics`、`metrics`、`dns_cache`。新增时要在 `nginx_conf/in_http_block.conf` 的 `lua_shared_dict` 中声明。

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

### 6.6 新增 config section

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

**注意**：`add()`/`delete()` 的 index 读写存在竞态条件。

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

### 9.3 测试脚本位置

- 单元测试：`test/v2/spec/*.spec.lua`
- 集成测试：`test/v2/test_integration.py`
- Docker Compose：`test/v2/docker-compose.yml`

### 9.4 单元测试覆盖

| Spec 文件 | 覆盖范围 |
|-----------|----------|
| `config_spec.lua` | 配置 schema 验证、默认值填充 |
| `context_spec.lua` | 请求上下文 ctx API |
| `core_spec.lua` | 核心模块 smoke test |
| `filter_challenge_spec.lua` | Challenge 规则过滤 |
| `ip_reputation_spec.lua` | IP 声誉评分、信号、白名单 |
| `ip_reputation_concurrency_spec.lua` | IP 声誉并发安全 |
| `ip_reputation_observability_spec.lua` | IP 声誉可观测性 |
| `matcher_spec.lua` | 10 种匹配器单元测试 |
| `plugin_terminal_actions_spec.lua` | 插件 terminal action 处理 |
| `rule_engine_challenge_spec.lua` | 规则引擎 challenge 流程 |
| `security_challenge_xss_spec.lua` | JS Challenge XSS 安全 |
| `security_cookie_bypass_spec.lua` | Cookie 验证绕过防护 |
| `waf_hits_spec.lua` | WAF 命中记录 |
| `waf_rule_manager_spec.lua` | WAF 规则 CRUD + 版本控制 |

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

mutating 请求可携带 `Idempotency-Key` header，重复 key 返回 409（1 小时 TTL，基于 `vn_locks`）。

### 10.7 响应大小限制

API 响应超过 10MB 截断为 413。

### 10.8 SSRF 防护

所有 webhook URL 必须：
- 以 `https://` 开头
- 不指向私有 IP 段（`127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`）

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

---

## 附录：模块文件结构

```
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
│   │   │   ├── frequency.lua ← 频率限制
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
│   │   └── waf_recommender.lua
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