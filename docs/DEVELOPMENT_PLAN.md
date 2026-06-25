# VeryNginx v2.0 开发计划

> 基于 `DESIGN_V2.md` 的详细开发任务拆解。每个阶段可独立验证，阶段间有明确的依赖关系。

---

## 环境准备

### 开发环境要求

| 项目 | 要求 |
|------|------|
| OpenResty | 1.19+（含 `lua-resty-core`、`lua-resty-dns-resolver`） |
| LuaJIT | 2.1+ |
| Lua 包管理 | `luarocks` + `busted` |
| 测试工具 | `wrk` / `vegeta` / `Test::Nginx::Socket` |
| 静态检查 | `luacheck` |
| 代码版本 | Git |

### 目录初始化

```bash
# v2 核心代码放在 verynginx/ 下，与 v1.x 的 lua_script/ 并列
# 新目录结构：
cd verynginx
mkdir -p core matcher action plugin/filter plugin/frequency_limit \
  plugin/browser_verify plugin/router plugin/proxy_pass plugin/static_file \
  plugin/summary api nginx_conf configs/backups support
```

### 代码风格规范

- Lua 文件头：`-- -*- coding: utf-8 -*-` + `@Date` + `@Author`（复用 v1.x 风格）
- 缩进：4 空格（与 v1.x 一致）
- 命名：`snake_case` 函数名，`_M` 模块变量
- 模块导出：统一 `return _M`
- require 路径：以 `verynginx/` 为 root，用 `.` 分隔路径（如 `require "core.config"`）

### 可复用的 v1.x 资源

以下文件可直接复制或引用：

| v1.x 文件 | v2 用途 |
|-----------|---------|
| `lua_script/module/dkjson.lua` | JSON 编码（dkjson.encode） |
| `lua_script/module/json.lua` | JSON 解码（json.decode） |
| `lua_script/module/cookie.lua` | Cookie 读取（`matcher/cookie.lua` 和 `api/auth.lua` 的 cookie 模块） |
| `lua_script/resty/dns/resolver.lua` | DNS 解析（`plugin/proxy_pass/dns_cache.lua`） |
| `dashboard/` | 管理面板前端资源（可直接复用，Phase 7 接入新 API） |
| `support/verify_javascript.html` | 浏览器验证页面（`plugin/browser_verify`） |

---

## Phase 1 — 核心框架

> 对应 DESIGN_V2.md 第 4.1、4.2、4.4、4.5 节 + 第 5.1 节
> **依赖**：无（从零搭建）
> **产出**：可启动的空框架（Nginx 启动 + 插件注册 + 配置加载）

### 1.1 基础工具模块

| 任务 | 文件 | 说明 | 参考设计 |
|------|------|------|---------|
| 1.1.1 | `core/random.lua` | 安全随机数封装：`bytes(n)` / `hex(n)` | Section 4.7 辅助模块接口 |
| 1.1.2 | `action/response.lua` | 响应解析器：`resolve(def)` → 模板查找 / 内联解析 | Section 4.4 response.resolve() |

**入口**：O（2 个文件，约 40 行 Lua）
**验证**：`busted` 单元测试覆盖 `random.bytes`、`response.resolve(字符串)`、`response.resolve(table)`、`response.resolve(nil)`

---

### 1.2 配置管理

| 任务 | 文件 | 说明 | 参考设计 |
|------|------|------|---------|
| 1.2.1 | `core/config.lua` | 核心配置模块：schema 定义、load_from_file、save、rollback、validate_and_compile（含 normalize_defaults + compile_runtime_snapshot） | Section 4.1 |
| 1.2.2 | `configs/config.json` | 默认配置文件（最小启动配置） | Section 9 |
| 1.2.3 | `configs/.gitkeep` | 占位文件，保留 backups/ 目录 | — |

**入口**：O（2 个主文件 + 2 个辅助文件，约 300 行 Lua）
**关键实现点**：
- `_M.schema` 完整定义（Section 9 所有字段）
- `_M.save()` 实现 token 锁 + `refresh_save_lock` + `release_save_lock`
- `_M.load_from_file()` 实现双重检查（config_save_lock 存在时不读文件）
- `_M.make_backup()` 实现复制 + 修剪
- `_M.rollback()` 实现备份恢复
- `_M.check_update()` 实现 hash 比较（零文件 I/O）

**依赖**：1.1.1（random.bytes）、1.1.2（response.resolve 用于内部响应）
**验证**：
- `busted`：load_from_file / save / rollback / check_update / 并发锁 / token 校验
- 启动加载测试：Nginx 启动时 config.json 加载成功
- `validate_and_compile` 拒绝未知 matcher/action/plugin

---

### 1.3 请求上下文

| 任务 | 文件 | 说明 | 参考设计 |
|------|------|------|---------|
| 1.3.1 | `core/context.lua` | 请求上下文模块：new、get_body_args、get_uri_args、set_action、has_decision、clear_action、set_data、get_data | Section 4.2 |

**入口**：1 个文件，约 100 行 Lua
**关键实现点**：
- `_M.new()` 创建完整的 ctx 表（含所有字段和方法引用）
- `get_body_args` 实现延迟读取 + body 大小限制 + body 落盘处理
- `match_cache` 上限控制
- `trace_id` 生成逻辑

**依赖**：无（纯功能封装，不依赖其他模块）
**验证**：`busted`：new 返回正确结构 / get_body_args 延迟读取 / set_action + has_decision / set_data + get_data / match_cache 上限

---

### 1.4 插件系统

| 任务 | 文件 | 说明 | 参考设计 |
|------|------|------|---------|
| 1.4.1 | `core/plugin.lua` | 插件注册中心：register、is_enabled、handle_error、init_all、execute_access、execute_log | Section 4.5 |

**入口**：1 个文件，约 100 行 Lua
**关键实现点**：
- `_M.plugins` 注册表 + 按 priority 排序
- `is_enabled` 读取 `config.plugin[plugin.name].enable`
- `handle_error` 中 `critical` 插件触发 fail-closed（调用 `ctx.set_action("block", ...)`）
- `execute_access` 短路：`ctx.has_decision(ctx)` 时 `break`

**依赖**：1.3（context）、1.2（config.plugin 读取）
**验证**：`busted`：register + 排序 / is_enabled 配置覆盖 / handle_error critical/fail-open / execute_access 短路

---

### 1.5 初始化入口

| 任务 | 文件 | 说明 | 参考设计 |
|------|------|------|---------|
| 1.5.1 | `core/init.lua` | 主初始化入口：init（加载配置 + 初始化共享内存 + 注册匹配器 + 注册插件 + 初始化插件）+ init_worker（metrics + observability + statistics + health_check） | Section 5.1 |

**入口**：1 个文件，约 60 行 Lua
**关键实现点**：
- `_M.init()` 调用 `config.load_from_file()` 等
- `_M.init_worker()` 按顺序初始化各模块
- `init_shared_dict()` 设置 `config_hash`

**依赖**：1.2（config）、1.3（context）、1.4（plugin）
**验证**：Nginx 启动测试：`init_by_lua` + `init_worker_by_lua` 不抛出异常

---

### 1.6 Nginx 配置骨架

| 任务 | 文件 | 说明 | 参考设计 |
|------|------|------|---------|
| 1.6.1 | `nginx_conf/in_external.conf` | 外部配置（upstream、lua 路径） | Section 7.1 |
| 1.6.2 | `nginx_conf/in_http_block.conf` | HTTP 块配置（lua_shared_dict、init、init_worker） | Section 7.1 |
| 1.6.3 | `nginx_conf/in_server_block.conf` | Server 块配置（location、阶段入口） | Section 7.2 |
| 1.6.4 | `on_rewrite.lua` | rewrite 阶段入口（检查配置 + 创建 ctx + scheme_lock + redirect + rewrite + apply） | Section 5.2 |
| 1.6.5 | `on_access.lua` | access 阶段入口（检查 ctx + 执行插件 + apply） | Section 5.3 |
| 1.6.6 | `on_log.lua` | log 阶段入口（执行插件日志钩子） | Section 5.4 |

**入口**：6 个文件，约 100 行 Lua + Nginx 配置
**关键实现点**：
- 三个 `.conf` 文件的 lua_shared_dict 声明必须与 Section 7.1 一致
- `on_rewrite.lua` 调用 `config.check_update()` 和 `context.new()`
- `on_access.lua` 调用 `plugin.execute_access(ctx)` + `rule_engine.apply(ctx, "access")`
- `on_log.lua` 调用 `plugin.execute_log(ctx)`

**依赖**：1.5（init）、1.3（context）、1.2（config）、1.4（plugin）
**验证**：Nginx 启动 + `init_by_lua` 执行无报错

---

### Phase 1 验收清单

> 对应 DESIGN_V2.md 13.1

- [ ] 配置保存经过 schema 校验、引用完整性校验和编译校验
- [ ] 保存流程支持带 token 的并发锁、TTL 续期、tmp 文件、原子 rename、备份、回滚
- [ ] 运行时配置是不可变快照，插件不得直接修改
- [ ] `busted` 单元测试覆盖 config、context、plugin、response.resolve、random

---

## Phase 2 — 匹配器与规则引擎

> 对应 DESIGN_V2.md 第 4.3、4.4 节
> **依赖**：Phase 1（config、context、rule_engine 的 apply 骨架）
> **产出**：可配置 WAF 规则的框架

### 2.1 匹配器注册中心

| 任务 | 文件 | 说明 |
|------|------|------|
| 2.1.1 | `matcher/init.lua` | 匹配器注册中心：register、test（含缓存） |

**入口**：1 个文件，约 40 行 Lua
**关键实现点**：
- `_M.test(matcher_def, ctx)` 遍历条件，AND 语义
- 缓存命中 + 上限控制
- 未知条件类型运行期返回 false

**依赖**：1.3（ctx.match_cache）
**验证**：`busted`：空匹配器 / 单条件 / 多条件 AND / 缓存命中 / 缓存上限 / 未知条件

---

### 2.2 具体匹配器

| 任务 | 文件 | 运算符支持 |
|------|------|-----------|
| 2.2.1 | `matcher/uri.lua` | = ≈ !≈ * |
| 2.2.2 | `matcher/ip.lua` | = ≈ !≈ * |
| 2.2.3 | `matcher/ua.lua` | = ≈ !≈ * |
| 2.2.4 | `matcher/host.lua` | = ≈ !≈ * |
| 2.2.5 | `matcher/referer.lua` | = ≈ !≈ * |
| 2.2.6 | `matcher/args.lua` | name_operator + operator + on_body_error 语义（延迟读 body） |
| 2.2.7 | `matcher/header.lua` | name_operator + operator（test_many_var 模式） |
| 2.2.8 | `matcher/cookie.lua` | name_operator + operator（复用 `lua_script/module/cookie.lua`） |
| 2.2.9 | `matcher/method.lua` | = ≈ !≈ * |
| 2.2.10 | `matcher/composite.lua` | AND / OR / NOT 组合 |

**入口**：10 个文件，每文件约 20-50 行 Lua
**关键实现点**：
- `matcher/args.lua` 实现延迟读 body + `on_body_error` 三种策略
- `matcher/cookie.lua` 复用 v1.x 的 `cookie` 模块
- `matcher/composite.lua` 实现嵌套组合的递归匹配
- 每个匹配器函数签名为 `test(condition, ctx) → bool`
- 正则在配置加载阶段预编译（PCRE JIT），运行期只执行

**依赖**：2.1（注册中心）、1.3（ctx 的 body 延迟读取）
**验证**：`busted`：10 个匹配器，每个覆盖所有运算符 + 边界条件 + on_body_error 三种策略

---

### 2.3 动作注册中心

| 任务 | 文件 | 说明 |
|------|------|------|
| 2.3.1 | `action/init.lua` | 动作注册中心：register、execute（action_handler 分派） |

**入口**：1 个文件，约 30 行 Lua
**关键实现点**：
- `_M.execute(action_type, rule, ctx)` 查找 handler 并调用
- handler 返回 `{ type = RESULT.PASS }` 或决策结果

**验证**：`busted`：register / execute / 未知 action 处理

---

### 2.4 具体动作

| 任务 | 文件 | 说明 |
|------|------|------|
| 2.4.1 | `action/accept.lua` | 放行：返回 `{ type = "accept" }` |
| 2.4.2 | `action/block.lua` | 拦截：返回 `{ type = "block", data = { code, response } }` |
| 2.4.3 | `action/redirect.lua` | 重定向：返回 `{ type = "redirect", data = { url, code } }` |
| 2.4.4 | `action/rewrite.lua` | URI 重写：返回 `{ type = "rewrite", data = { uri } }` |
| 2.4.5 | `action/scheme_lock.lua` | Scheme 锁定：返回 `{ type = "redirect", data = { scheme } }` |

**入口**：5 个文件，每文件约 15-30 行 Lua
**依赖**：2.3（注册中心）
**验证**：`busted`：每个 action 返回正确的 result type + data 结构

---

### 2.5 规则引擎

| 任务 | 文件 | 说明 |
|------|------|------|
| 2.5.1 | `core/rule_engine.lua` | 规则引擎：execute（规则链 + 短路）+ apply（动作落地到 Nginx） |

**入口**：1 个文件，约 80 行 Lua
**关键实现点**：
- `RESULT` 常量表（8 种类型）
- `_M.execute(rules, ctx)` 遍历规则，匹配后返回决策
- `_M.apply(ctx, phase)` 根据 phase 限制生效动作（rewrite 只在 rewrite 阶段）
- PROXY 动作设置 nginx 变量（vn_proxy_*）
- BLOCK/REDIRECT/RESPONSE 调用 `ngx.exit`
- STATIC 调用 `static_file.serve()`（骨架）

**依赖**：2.1（matcher.test）、2.3（action.execute）、1.1.2（response.resolve）
**验证**：`busted`：execute 短路 / apply BLOCK / apply REDIRECT / apply RESPONSE / apply REWRITE 阶段限制 / apply PROXY 变量设置

---

### 2.6 配置编译校验增强

| 任务 | 文件 | 说明 |
|------|------|------|
| 2.6.1 | `core/config.lua`（增强） | 在 validate_and_compile 中增加 matcher 引用校验、action 引用校验、upstream 引用校验、response 模板引用校验、on_body_error 取值校验 |

**入口**：增强已有文件，约 +50 行 Lua
**关键实现点**：
- 遍历 `config.rule` 的所有规则，检查 matcher/action/response/upstream 存在性
- 检查 `condition.on_body_error` 只取合法值
- 检查 upstream 必须声明 health_check/tls/timeout

**依赖**：2.1~2.4（完整的 matcher + action 注册表）
**验证**：`busted`：合法配置通过 / 缺失 matcher 拒绝 / 缺失 action 拒绝 / on_body_error 非法值拒绝

---

### Phase 2 验收清单

> 对应 DESIGN_V2.md 13.3、13.4

- [ ] 所有 10 种匹配器可注册和测试
- [ ] 5 种动作可注册和测试
- [ ] 规则引擎短路生效：匹配后停止后续规则
- [ ] block/redirect 立即终止，rewrite 只在 rewrite 阶段生效
- [ ] Body matcher 受 `max_size`、`max_args` 限制
- [ ] `condition.on_body_error` 三种策略生效
- [ ] 组合 matcher 支持 AND/OR/NOT
- [ ] 配置编译时拒绝未知 matcher/action/plugin
- [ ] `busted` 单元测试覆盖全部 matcher + action + rule_engine

---

## Phase 3 — 安全基线

> 对应 DESIGN_V2.md 第 4.7 节 + 辅助模块接口
> **依赖**：Phase 1（config、context、plugin 骨架）
> **产出**：管理接口安全可用

### 3.1 安全辅助模块

| 任务 | 文件 | 说明 |
|------|------|------|
| 3.1.1 | `core/session.lua` | HMAC session 签名/验证：sign(payload, secret) / verify(token, secret) |
| 3.1.2 | `core/password_hash.lua` | 密码哈希/校验：hash(password) / verify(password, hash) |
| 3.1.3 | `core/random.lua` | （Phase 1.1.1 已完成，留空） |

**入口**：2 个文件，每文件约 40-60 行 Lua
**关键实现点**：
- `session.sign` 使用 HMAC-SHA256，payload 含 expire_at + nonce + user
- `session.verify` 校验签名 + 过期时间
- `password_hash` 优先 bcrypt/argon2（`lua-resty-bcrypt` 或 `lua-resty-argon2`），不支持时拒绝启动
- 密钥轮换：`config.security.session_secret` 支持主/备双密钥

**验证**：`busted`：sign/verify 往返 / 过期拒绝 / 签名篡改拒绝 / 密钥轮换 / password_hash 正确性

---

### 3.2 API 基础模块

| 任务 | 文件 | 说明 |
|------|------|------|
| 3.2.1 | `api/rate_limit.lua` | 限流：allow(key) / allow(key, limit, window) |
| 3.2.2 | `api/csrf.lua` | CSRF 令牌：generate(ctx) / verify(ctx) |

**入口**：2 个文件，每文件约 30-50 行 Lua
**关键实现点**：
- `rate_limit.allow` 使用 `ngx.shared.vn_locks` 或独立 shared dict（配置中增加 `lua_shared_dict rate_limit` 可选项）
- `csrf.generate` 使用 `random.bytes(32)` 写入 ctx.data
- `csrf.verify` 对比请求头中的 CSRF token

**验证**：`busted`：rate_limit 正常/超限 / CSRF generate/verify / token 不匹配拒绝

---

### 3.3 认证模块

| 任务 | 文件 | 说明 |
|------|------|------|
| 3.3.1 | `api/auth.lua` | 认证中间件：注册策略 + session-based 默认策略 + middleware(ctx) |

**入口**：1 个文件，约 80 行 Lua
**关键实现点**：
- `_M.middleware(ctx)` 调用 `strategy.check(ctx)` + `csrf.verify(ctx)`（变更型 API）
- 登录接口 `rate_limit.allow("login:<ip>")` 限流
- Cookie 设置 `HttpOnly; SameSite=Strict`，HTTPS 下追加 `Secure`
- 管理员密码只保存 `password_hash`

**依赖**：3.1（session/password_hash）、3.2（rate_limit/csrf）、1.3（ctx）
**验证**：
- `busted`：login 成功/失败/限流 / session 校验 / CSRF 拦截 / Cookie 标志
- 安全测试：CSRF token 缺失拒绝 / 登录爆破限流

---

### 3.4 API 路由注册

| 任务 | 文件 | 说明 |
|------|------|------|
| 3.4.1 | `api/init.lua` | API 路由注册：URL → handler 映射 |

**入口**：1 个文件，约 30 行 Lua
**关键实现点**：
- 注册 `/login`、`/config`（GET/POST）、`/status`、健康检查等路径
- 每个路由指定是否需要认证（auth 中间件）
- 变更型 API 路径标记为 `mutating`，触发 CSRF 校验

**验证**：Nginx 集成测试：登录 → 获取 config → 修改 config → 登出

---

### Phase 3 验收清单

> 对应 DESIGN_V2.md 13.2

- [ ] 管理员密码哈希存储
- [ ] Session 签名、过期时间、密钥轮换
- [ ] 变更型 API 启用 CSRF
- [ ] 登录/配置保存/回滚接口限流
- [ ] Cookie HttpOnly + SameSite=Strict，HTTPS 下 Secure
- [ ] 代理 TLS 默认校验证书和 SNI
- [ ] `busted` 单元测试覆盖 auth/session/password_hash/rate_limit/CSRF

---

## Phase 4 — 防护插件实现

> 对应 DESIGN_V2.md 第 6.1、6.3、6.4、6.6 节
> **依赖**：Phase 2（matcher + rule_engine）
> **产出**：WAF + 频率限制 + 浏览器验证 + 静态文件服务完整实现

### 4.1 防火墙插件

| 任务 | 文件 | 说明 |
|------|------|------|
| 4.1.1 | `plugin/filter/init.lua` | 插件入口：读取 config.rule.filter，执行匹配→block/accept |
| 4.1.2 | `plugin/filter/rules.lua` | 默认规则集（SQL注入、备份文件、扫描工具、代码仓库泄露） |
| 4.1.3 | `plugin/filter/matcher.lua` | filter 专用辅助匹配函数 |

**入口**：3 个文件，约 100 行 Lua
**关键实现点**：
- 复用 `matcher.test()` + `rule_engine` 的 execute/apply 框架
- 默认规则集从 v1.x 的 `VeryNginxConfig.lua` 中的默认 matcher 移植
- accept 规则的 semantics：终止当前插件链，放行到后续 Nginx 流程
- block 设置 `ctx.data["filter:blocked"] = true`

**依赖**：2.1（matcher.test）、2.5（rule_engine 的 execute/apply）
**验证**：
- `busted`：规则匹配 / accept 短路 / block 响应
- 集成测试：SQL注入请求被拦截 / 正常请求放行

---

### 4.2 频率限制插件

| 任务 | 文件 | 说明 |
|------|------|------|
| 4.2.1 | `plugin/frequency_limit/init.lua` | 插件入口：读取 config.rule.frequency_limit，频次计数→block |
| 4.2.2 | `plugin/frequency_limit/limiter.lua` | key 构建函数：build_key(key_def, ctx) |

**入口**：2 个文件，约 80 行 Lua
**关键实现点**：
- `build_key` 支持 ip/uri/user/combo 四种维度
- `ngx.shared.frequency_limit:incr(key, 1, 0, window)` 带窗口 TTL
- 超限时设置 `ctx.data["frequency_limit:limited"] = true`
- 未登录用户使用 `anonymous`

**依赖**：2.1（matcher.test）、1.3（ctx.data）
**验证**：
- `busted`：build_key 各种维度 / 限流命中 / TTL 过期恢复
- 集成测试：短时间多发请求被 429

---

### 4.3 浏览器验证插件

| 任务 | 文件 | 说明 |
|------|------|------|
| 4.3.1 | `plugin/browser_verify/init.lua` | 插件入口：Cookie/JS 验证流程 |
| 4.3.2 | `plugin/browser_verify/cookie_verify.lua` | Cookie 验证（使用 core/session.lua 签名） |
| 4.3.3 | `plugin/browser_verify/javascript_verify.lua` | JS 验证（返回验证页面） |

**入口**：3 个文件，约 120 行 Lua（参考 v1.x browser_verify.lua）
**关键实现点**：
- Cookie 签名改用 `core/session.lua`
- JS 验证页面复用 `support/verify_javascript.html`
- 验证通过后设置 `ctx.data["browser_verify:passed"] = true`
- 验证失败时返回 `response` action（引用 config.response 模板）

**依赖**：3.1（session.lua）、1.1.2（response.resolve）
**验证**：集成测试：未验证客户端收到 302 或验证页面 / 已验证客户端放行

---

### 4.4 静态文件服务

| 任务 | 文件 | 说明 |
|------|------|------|
| 4.4.1 | `plugin/static_file/init.lua` | 插件入口 + serve() 函数 |

**入口**：1 个文件，约 80 行 Lua
**关键实现点**：
- `serve(root, path, expires)` 实现路径安全检查
- 大文件使用 `X-Accel-Redirect`（阈值 `config.static_file.x_accel_threshold`）
- `normalize(root, path)` 拒绝 `..` / NUL / URL 编码绕过
- 文件不存在返回 404，不 fall-through

**依赖**：2.1（matcher.test）
**验证**：
- `busted`：路径归一化 / 越权拒绝 / 大文件分流 / 404 行为
- 集成测试：请求静态文件返回正确内容

---

### Phase 4 验收清单

> 对应 DESIGN_V2.md 13.3、13.4

- [ ] Filter 插件：WAF 规则可配置并生效
- [ ] Frequency_limit 插件：限流规则可配置并生效
- [ ] Browser_verify 插件：Cookie/JS 验证可配置并生效
- [ ] Static_file 插件：静态文件服务可配置，路径安全
- [ ] 关键插件（filter/frequency_limit/browser_verify）默认 fail-closed
- [ ] 所有插件复用统一规则结构（config.rule.*）
- [ ] `busted` 测试 + 集成测试覆盖 4 个插件

---

## Phase 5 — 动态代理

> 对应 DESIGN_V2.md 第 6.2、6.5、6.7 节 + 4.8 节
> **依赖**：Phase 2（matcher + rule_engine）
> **产出**：反向代理 + 健康检查 + DNS 缓存 + WebSocket

### 5.1 反向代理插件 + 负载均衡

| 任务 | 文件 | 说明 |
|------|------|------|
| 5.1.1 | `plugin/proxy_pass/init.lua` | 代理插件入口：读取规则→选择健康节点→设置变量 |
| 5.1.2 | `plugin/proxy_pass/balancer.lua` | 负载均衡器：select_healthy(upstream) + run()（balancer_by_lua 阶段调用） |

**入口**：2 个文件，约 100 行 Lua
**关键实现点**：
- `select_healthy()` 只从 `is_healthy()` 返回 true 的节点中选择
- `run()` 读取 `ngx.var.vn_proxy_host` / `vn_proxy_port` → `set_current_peer`
- 支持 round_robin、ip_hash、weighted_random 三种方法
- 无健康节点时返回 503

**依赖**：5.2（health_check.is_healthy）、2.1（matcher.test）、1.2（config.backend_upstream）
**验证**：
- `busted`：select_healthy 只返回健康节点 / 无健康节点返回 nil / 轮询分布
- 集成测试：balancer_by_lua 转发到正确后端

---

### 5.2 健康检查

| 任务 | 文件 | 说明 |
|------|------|------|
| 5.2.1 | `plugin/proxy_pass/health_check.lua` | 主动/被动健康检查：init、active_check_all、check_node、probe_node、report_failure、is_healthy |

**入口**：1 个文件，约 80 行 Lua（参考 Section 4.8 完整实现）
**关键实现点**：
- `check_node()` 探测成功时清理 state/failures/last_error，恢复 healthy
- `probe_node()` 根据配置执行 TCP 或 HTTP 探测
- `is_healthy()` 检查 state ≠ "unhealthy"
- 健康状态放入 `lua_shared_dict healthcheck`

**依赖**：1.4（plugin.register 的 on_init 钩子）、4.9（metrics.gauge）
**验证**：
- `busted`：check_node 恢复 / report_failure 摘除 / is_healthy 判断
- 集成测试：故障节点摘除 + 恢复后重新加入

---

### 5.3 Router 插件

| 任务 | 文件 | 说明 |
|------|------|------|
| 5.3.1 | `plugin/router/init.lua` | 管理路径路由：识别 /verynginx/* 路径，委托给 API 模块 |

**入口**：1 个文件，约 40 行 Lua
**关键实现点**：
- 匹配 `base_uri` 前缀
- 设置 `ctx.data["router:target"]` 标识管理请求
- 静态资源走 `nginx_conf` 中定义的 location
- 认证委托给 `api/auth.lua`

**依赖**：3.3（auth）、3.4（api routing）
**验证**：集成测试：管理路径返回登录页面 / 非管理路径不拦截

---

### 5.4 DNS 缓存

> 对应 DESIGN_V2.md 第 6.7 节

| 任务 | 文件 | 说明 |
|------|------|------|
| 5.4.1 | `plugin/proxy_pass/dns_cache.lua` | DNS 解析缓存：cache_key、resolve、effective_ttl、resolve_stale |

**入口**：1 个文件，约 60 行 Lua
**关键实现点**：
- 缓存 key：`dns:<lowercase-host>:<record-type>`
- `effective_ttl` 用 min/max 覆盖原始 TTL
- `stale_if_error` 失效后额外保留期
- 配置变更时清除相关 key

**依赖**：1.2（config.backend_upstream.dns）
**验证**：
- `busted`：cache_key 生成 / TTL 覆盖 / stale 生效 / 配置变更失效
- 集成测试：DNS 查询缓存命中 / 解析失败后 stale 值返回

---

### Phase 5 验收清单

> 对应 DESIGN_V2.md 13.5

- [ ] 代理使用健康节点选择
- [ ] 主动健康检查 + 被动失败计数已实现
- [ ] 无健康节点返回 503
- [ ] WebSocket 集成测试覆盖
- [ ] 动态代理不依赖 `ngx.exec`
- [ ] upstream 配置包含 nodes、health_check、tls、timeout
- [ ] DNS cache 定义 key 格式、TTL 覆盖、stale-if-error、失效触发和内存预算
- [ ] balancer 阶段读取 access 阶段已选节点

---

## Phase 6 — 可观测性

> 对应 DESIGN_V2.md 第 4.6、4.9 节
> **依赖**：Phase 1（config、plugin）+ Phase 2（rule_engine）+ Phase 5（proxy_pass）
> **产出**：统计、metrics、trace 完整实现

### 6.1 Metrics 指标封装

| 任务 | 文件 | 说明 |
|------|------|------|
| 6.1.1 | `core/metrics.lua` | （Phase 1 骨架中已创建）完整实现：init、incr、observe、gauge、export_prometheus |

**入口**：增强已有文件，约 +50 行 Lua
**关键实现点**：
- `init()` 创建 `__metrics_index`（幂等）
- `export_prometheus()` 从受控 index 导出 Prometheus 文本格式
- labels 序列化到 key（如 `plugin_errors_total{plugin="filter"}`）
- 不在请求路径调用 `get_keys(0)`

**验证**：`busted`：incr/observe/gauge 正确增量 / label 序列化 / export 格式 / 幂等 init

---

### 6.2 可观测性模块

| 任务 || 6.2.1 | `core/observability.lua` | （Phase 1 骨架中已创建）完整实现：init、start_plugin_timer、finish_plugin_timer、export_prometheus |

**入口**：增强已有文件，约 +40 行 Lua
**关键实现点**：
- `start_plugin_timer` / `finish_plugin_timer` 通过 `ctx.data["timing:<name>"]` 记录耗时
- `export_prometheus` 汇总 metrics + 插件耗时 + 上游健康状态 + 配置版本
- access log 中输出 `trace_id`、动作结果、插件耗时、upstream 目标

**验证**：`busted`：timer 开始/结束 / trace_id 生成 / access log 格式

---

### 6.3 统计引擎

| 任务 | 文件 | 说明 |
|------|------|------|
| 6.3.1 | `plugin/summary/init.lua` | Summary 插件入口：on_log 中调用 statistics.log_request(ctx) |
| 6.3.2 | `plugin/summary/collector.lua` | 统计收集函数（可选，如果 statistics.lua 已完整则可为空） |
| 6.3.3 | `plugin/summary/reporter.lua` | 统计报告函数（可选，如果 statistics.lua 已完整则可为空） |
| 6.3.4 | `core/statistics.lua` | （Phase 1 骨架中已创建）完整实现：init、log_request、normalize_uri、add_index、get_index、report、persist |

**入口**：4 个文件，约 150 行 Lua
**关键实现点**：
- `log_request` 每请求写 1m 桶（count/bytes/time/status），不写多桶
- `add_index(bucket, uri)` 写入 `index:<bucket>` 受控 LRU 列表
- `get_index(bucket)` 只从 index 读取，禁止 `get_keys(0)`
- `normalize_uri` 把 `/user/123/order/456` 归一为 `/user/:id/order/:id`（可配置模式）
- `persist` 定时把长期桶写入 `configs/statistics.json`，启动时恢复
- summary 插件的 `on_log` 简单调用 `statistics.log_request(ctx)`

**验证**：
- `busted`：log_request 写入 / add_index 不超过 max_uri_keys / normalize_uri / persist 读写 / report 格式
- 集成测试：多次请求后 status 报告正确计数

---

### 6.4 API 控制器

| 任务 | 文件 | 说明 |
|------|------|------|
| 6.4.1 | `api/config_controller.lua` | 配置 CRUD：GET /config、POST /config |
| 6.4.2 | `api/status_controller.lua` | 状态查询：GET /status |
| 6.4.3 | `api/metrics_controller.lua` | Metrics 导出：GET /metrics |
| 6.4.4 | `api/summary_controller.lua` | 统计查询：GET /summary |

**入口**：4 个文件，每文件约 30-50 行 Lua
**关键实现点**：
- config_controller GET 返回 `config.report()`，POST 调用 `config.save()`
- status_controller 返回 `observability.export_prometheus()` 或状态摘要
- metrics_controller 返回 prometheus 格式
- summary_controller 返回 `statistics.report(period)`

**依赖**：1.2（config）、3.3（auth）、3.4（api routing）、6.1（metrics）、6.2（observability）、6.3（statistics）
**验证**：集成测试：GET /config 返回当前配置 / POST /config 更新配置 / GET /metrics 返回 Prometheus 格式 / GET /summary 返回统计

---

### 6.5 持久化

| 任务 | 文件 | 说明 |
|------|------|------|
| 6.5.1 | `core/statistics.lua`（增强） | 实现 `_M.persist()`：定时写入 statistics.json + 启动时恢复 |
| 6.5.2 | `configs/statistics.json` | 启动时生成的持久化统计文件（自动创建） |

**入口**：增强已有文件，约 +30 行 Lua
**关键实现点**：
- `persist()` 使用 tmp + rename 原子写入
- 启动时从 `statistics.json` 恢复 `summary_long` 桶
- 启动时恢复功能由 `statistics.init()` 触发

**验证**：`busted`：persist 写入 / 恢复读取 / 格式校验

---

### Phase 6 验收清单

> 对应 DESIGN_V2.md 13.6

- [ ] 统计 key 归一化并限制基数
- [ ] 长期统计持久化并支持启动恢复
- [ ] `/metrics` 导出 Prometheus 格式指标
- [ ] 请求携带 `trace_id`，透传到后端
- [ ] 插件耗时、动作结果、上游选择结果可记录
- [ ] `busted` 单元测试 + 集成测试覆盖统计、metrics、trace

---

## Phase 7 — 管理面板 + 全量测试

> 对应 DESIGN_V2.md 第 10 节 + Section 13.7
> **依赖**：Phase 1~6 全部完成
> **产出**：可上线的完整版本

### 7.1 管理面板接入

| 任务 | 文件 | 说明 |
|------|------|------|
| 7.1.1 | `dashboard/`（适配） | 修改 v1.x 的 dashboard HTML/JS 以调用 v2 API 路径和响应格式 |
| 7.1.2 | `nginx_conf/in_server_block.conf`（增强） | 完善 `/verynginx/static/` location 配置 |

**入口**：适配已有文件
**关键实现点**：
- dashboard 的 API 调用路径改为 v2 的 `/verynginx/...` 格式
- 认证接口适配 v2 的 Cookie/Session 机制
- 配置编辑器适配 v2 的配置结构（rule、plugin、security 等新字段）

**验证**：集成测试：打开管理面板 → 登录 → 浏览状态 → 修改配置 → 登出

---

### 7.2 单元测试全覆盖

| 任务 | 覆盖范围 |
|------|---------|
| 7.2.1 | `matcher/*.lua`：10 个匹配器 × 所有运算符 + 边界条件 |
| 7.2.2 | `action/*.lua`：5 个 action × 正确的 result type |
| 7.2.3 | `core/rule_engine.lua`：短路 / apply 各类型 / 阶段限制 |
| 7.2.4 | `core/config.lua`：加载/保存/回滚/校验/并发锁/token |
| 7.2.5 | `core/context.lua`：body 延迟读取 / match_cache上限 / ctx.data |
| 7.2.6 | `core/plugin.lua`：注册/排序/启用/critical/fail-open |
| 7.2.7 | `core/session.lua`：签名/验证/过期/密钥轮换 |
| 7.2.8 | `core/password_hash.lua`：哈希/校验/降级拒绝 |
| 7.2.9 | `api/auth.lua`：登录/登出/限流/CSRF/Cookie 标志 |
| 7.2.10 | `api/rate_limit.lua`：正常/超限/TTL |
| 7.2.11 | `core/statistics.lua`：写入/index/归一化/持久化/恢复 |
| 7.2.12 | `core/metrics.lua`：incr/observe/gauge/export/幂等 |

**入口**：约 300+ 条测试用例
**工具**：`busted`
**验证**：所有测试通过，CI 门禁

---

### 7.3 集成测试

| 任务 | 覆盖范围 |
|------|---------|
| 7.3.1 | Nginx 启动：配置文件加载 + 插件注册 |
| 7.3.2 | Rewrite 阶段：scheme_lock、redirect、uri_rewrite |
| 7.3.3 | Access 阶段：filter block/accept、frequency_limit 限流、browser_verify 验证 |
| 7.3.4 | Proxy 阶段：balancer_by_lua 转发、健康检查摘除/恢复、WebSocket 代理 |
| 7.3.5 | API 端点：/login、/config GET/POST、/status、/metrics、/summary |
| 7.3.6 | 热更新：修改配置后验证多 worker 感知新配置 |
| 7.3.7 | DNS 缓存：缓存命中、stale-if-error、配置变更失效 |

**入口**：约 30+ 个测试场景
**工具**：`Test::Nginx::Socket` 或 Docker Compose（OpenResty + 测试后端）

---

### 7.4 安全测试

| 任务 | 覆盖范围 |
|------|---------|
| 7.4.1 | CSRF token 缺失拒绝 / token 不匹配拒绝 |
| 7.4.2 | Cookie HttpOnly / SameSite=Strict / Secure（HTTPS）验证 |
| 7.4.3 | 登录限流：连续失败后拒绝 |
| 7.4.4 | 配置保存限流：频繁保存被拒绝 |
| 7.4.5 | 密码哈希：config.json 中无明文密码 |

**入口**：约 10 个安全测试场景

---

### 7.5 性能测试 + 基线

| 任务 | 测试场景 | 目标 |
|------|---------|------|
| 7.5.1 | 空规则（仅空框架） | 记录 RPS + P99 延迟基线 |
| 7.5.2 | 100 条 filter 规则 | 对比空规则，评估规则引擎开销 |
| 7.5.3 | 1000 条 filter 规则 | 对比 100 条规则，评估扩展性 |
| 7.5.4 | 热更新压力测试 | 并发请求下反复保存，确保无 5xx 抖动 |
| 7.5.5 | 10k+ 并发连接 | 内存泄漏检测，长期运行稳定性 |
| 7.5.6 | 内存泄漏检测 | 长时间运行（12h+）后 RSS 稳定性 |

**入口**：6 个性能测试场景
**工具**：`wrk` 或 `vegeta`

---

### 7.6 CI 配置

| 任务 | 文件 | 说明 |
|------|------|------|
| 7.6.1 | `.github/workflows/ci.yml` | CI 流程：lint → busted → 集成测试 → 性能基线 |

**入口**：1 个 CI 配置文件
**门禁要求**：
- `luacheck` 静态检查通过
- `busted` 单元测试全部通过
- 集成测试全部通过
- 性能基线不退化（与上一次提交对比）

---

### Phase 7 验收清单

> 对应 DESIGN_V2.md 13.7

- [ ] `busted` 单元测试覆盖 matcher、rule_engine、config、auth、statistics
- [ ] OpenResty 集成测试覆盖 rewrite、access、log、balancer、health check
- [ ] 安全测试覆盖 CSRF、Cookie flags、登录限流、配置保存限流
- [ ] 性能测试记录空规则、100 条规则、1000 条规则的 RPS 和 P99
- [ ] CI 中静态检查、单元测试、集成测试全通过
- [ ] 管理面板可正常登录和使用

---

## 时间估算

| Phase | 任务 | 文件数 | 估算行数 | 估算工时 | 关键依赖 |
|-------|------|--------|---------|---------|---------|
| **Phase 1** | 核心框架 | 13 | ~600 | 3-4 天 | 无 |
| **Phase 2** | 匹配器 + 规则引擎 | 13 | ~450 | 3-4 天 | Phase 1 |
| **Phase 3** | 安全基线 | 7 | ~300 | 2-3 天 | Phase 1 |
| **Phase 4** | 防护插件 | 9 | ~400 | 3-4 天 | Phase 2 |
| **Phase 5** | 动态代理 | 5 | ~360 | 3-4 天 | Phase 2 |
| **Phase 6** | 可观测性 | 9 | ~400 | 3-4 天 | Phase 1,2,5 |
| **Phase 7** | 面板 + 全量测试 | — | ~300 测试 | 4-5 天 | Phase 1~6 |
| **合计** | | ~56 | ~2800 | 21-28 天 | |

---

## 依赖关系图

```
Phase 1 ──→ Phase 2 ──→ Phase 4
                     │        └──→ Phase 6
                     │              ↑
                     └──→ Phase 5 ──┘
                           ↑
Phase 3 (安全基线) ────────┤

Phase 7 (全量测试 + 面板) ←─── 全部
```

**解释**：
- Phase 1 是基础，任何其他 Phase 都不能先于它
- Phase 2（匹配器 + 规则引擎）和 Phase 3（安全基线）可以**并行开发**
- Phase 4（防护插件）依赖 Phase 2
- Phase 5（动态代理）依赖 Phase 2 + 3（Router 插件需要安全认证）
- Phase 6（可观测性）依赖 Phase 4 + 5（需要完整的插件执行结果）
- Phase 7 依赖全部 Phase，最后做

**并行优化建议**：
- 开发人员 A：Phase 1 → Phase 2 → Phase 4 → Phase 6
- 开发人员 B：Phase 1 → Phase 3 → Phase 5 → Phase 6
- 开发人员 A + B 合并：Phase 7
