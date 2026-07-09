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

每个 controller 暴露 `_M.register(api)`，`api` 是 `api/init.lua` 的 `_M`。Controller 之间不互相依赖。

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

当前 shared dict 名称：`vn_config`、`vn_locks`、`ip_reputation`、`frequency_limit`、`healthcheck`。新增时要在 `nginx_conf/in_http_block.conf` 的 `lua_shared_dict` 中声明。

---

## 4. IP 声誉引擎

### 4.1 challenge 通过后 `clear_score` + `record_challenge_pass`

- `clear_score(ip)` — 清空所有信号槽
- `record_challenge_pass(ip)` — 递增连续通过计数，达到阈值后加入自动白名单

### 4.2 自动白名单

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
    geoip_block = 5,       -- GeoIP 拦截
}
```

---

## 5. GeoIP

### 5.1 数据库文件存在 ≠ GeoIP 可用

数据库文件 `.mmdb` 在磁盘上不等于能查询，`lua-resty-maxminddb` 模块必须加载成功。`is_available()` 检查 `_db ~= nil` 而不是文件是否存在。

### 5.2 启动后下载的数据库要自动重载

`lookup()` 中检测到 `_db == nil` 时自动调用 `reload()`。

### 5.3 数据源：P3TERX GeoLite2-City

使用官方 MaxMind GeoLite2-City 数据库（~66MB），通过 P3TERX 镜像下载。

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

---

## 8. 前端 Dashboard

### 8.1 Vue 3 + Vite SPA

- 单文件 `dashboard/index.html`，包含 HTML 模板 + `<script setup>` + CSS
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

### 10.5 SSRF 防护

所有 webhook URL 必须：
- 以 `https://` 开头
- 不指向私有 IP 段（`127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`）

---

## 附录：模块文件结构

```
verynginx/
├── api/
│   ├── init.lua             ← 路由调度 + 中间件
│   ├── helpers.lua          ← 共享工具函数
│   ├── controllers/
│   │   ├── auth.lua         ← 登录/登出
│   │   ├── config.lua       ← 配置/状态/审计
│   │   ├── waf_rules.lua    ← WAF 规则 CRUD
│   │   ├── waf_stats.lua    ← WAF 统计/命中/时间线
│   │   ├── waf_recommender.lua ← 规则推荐
│   │   ├── reputation.lua   ← IP 声誉
│   │   ├── geoip.lua        ← GeoIP 查询/配置
│   │   ├── fingerprint.lua  ← TLS 指纹
│   │   ├── frequency.lua    ← 频率限制
│   │   └── plugins.lua      ← 插件管理/上游健康
│   ├── auth.lua             ← 认证 middleware
│   ├── csrf.lua
│   └── rate_limit.lua
├── core/
│   ├── init.lua, config.lua, plugin.lua, rule_engine.lua
│   ├── ip_reputation.lua, statistics.lua, session.lua
│   ├── geoip.lua, geoip_updater.lua, alerting.lua
│   ├── ja3.lua, fingerprint_db.lua
│   ├── metrics.lua, observability.lua
│   ├── audit.lua, context.lua, hmac.lua
│   ├── password_hash.lua, random.lua
│   └── waf_recommender.lua
├── plugin/
│   ├── filter/              ← WAF + IP 声誉 + GeoIP
│   ├── browser_verify/      ← JS Challenge + Cookie
│   ├── frequency_limit/
│   ├── proxy_pass/
│   ├── router/
│   ├── static_file/
│   └── summary/
├── dashboard/index.html     ← Vue 3 SPA
├── nginx_conf/
│   ├── in_http_block.conf   ← shared dict, lua_package_path
│   ├── in_external.conf     ← upstream, main context
│   └── in_server_block.conf
└── resty/
    └── maxminddb.lua        ← vendored lua-resty-maxminddb
```