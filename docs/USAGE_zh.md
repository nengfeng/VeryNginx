# VeryNginx v2 使用手册

## 概述

VeryNginx 是一款运行在 Nginx 内部的 Web 应用防火墙（WAF）、反向代理和请求管理工具。它通过 Nginx Lua 模块嵌入到 Nginx 的请求处理流程中，扩展了 Nginx 本身的功能，并提供 Web 管理界面。

### 请求处理流程

```
客户端请求
    │
    ▼
rewrite_by_lua (on_rewrite.lua)
    ├── 检查配置热更新（零磁盘 I/O，仅 MD5 哈希比对）
    ├── 创建请求上下文
    ├── scheme_lock 动作（强制 HTTP/HTTPS）
    ├── redirect 动作（URL 重定向）
    ├── rewrite 动作（内部 URI 重写）
    └── 执行决策
    │
    ▼
access_by_lua (on_access.lua)
    ├── 插件按优先级顺序执行（可短路）
    │   ├── 1. filter (WAF) - 优先级 100
    │   ├── 2. frequency_limit - 优先级 200
    │   ├── 3. browser_verify - 优先级 300
    │   ├── 4. router - 优先级 400
    │   ├── 5. proxy_pass - 优先级 500
    │   ├── 6. static_file - 优先级 600
    │   └── 7. summary - 优先级 900
    └── 最终决策
        ├── block    → 返回自定义状态码和内容
        ├── redirect → 302/301 跳转
        ├── response → 直接返回内容
        ├── proxy    → 设置代理变量，进入 proxy_pass
        ├── static   → 本地文件处理
        └── accept   → 默认反向代理
    │
    ▼
balancer_by_lua (balancer.lua)
    └── 动态上游节点选择（轮询 + 健康检查）
    │
    ▼
proxy_pass → 上游服务器
    │
    ▼
log_by_lua (on_log.lua)
    └── 插件日志钩子（统计、度量上报）
```

---

## 管理面板

### 访问

```
http://<your-server>/verynginx/index.html
```

### 默认凭据

- 用户名：`verynginx`
- 密码：首次安装后需通过 `python install.py hash-password` 生成并配置

### 面板功能

| 页面 | 功能 |
|---|---|
| 状态 | 实时连接数、流量、请求量、响应时间 |
| 配置 | 分标签页管理：匹配器、响应模板、插件、上游、系统设置、原始 JSON |
| 统计 | URI 级别的请求统计（1m/5m/1h/all） |
| 关于 | 版本信息、API 文档链接 |

---

## 匹配器（Matcher）

Matcher 是 VeryNginx 的核心概念，用于匹配 HTTP 请求。一个 Matcher 包含多个条件，当请求满足**所有**条件时，即命中该 Matcher。

### 内置 Matcher 类型

| 类型 | 匹配字段 | 示例 |
|---|---|---|
| IP | 客户端 IP 或 CDN 透传 IP | `192.168.1.0/24`, `10.0.0.1` |
| Host | 请求的 Host 头 | `example.com`, `*.example.com` |
| URI | 请求路径 | `/api/*`, `/admin` |
| UserAgent | User-Agent 头 | `*curl*`, `*bot*` |
| Referer | Referer 头 | `https://myapp.com/*` |
| Args | URL 查询参数 | `?action=delete` |
| Header | 任意请求头 | `X-Forwarded-Proto: https` |
| Cookie | Cookie 值 | `session_id=*` |
| Method | HTTP 方法 | `POST`, `GET` |
| Composite | 组合多个子 Matcher（与/或） | `(IP 在白名单) AND (URI 匹配 /api)` |

### Matcher 条件逻辑

- 当 Matcher 包含多个条件时，请求必须满足**全部**条件才匹配（AND 逻辑）
- `Composite` Matcher 可实现 `OR`、`NOT` 等复杂逻辑
- 条件值支持通配符 `*`（匹配任意字符）和 CIDR（IP 段）

### 配置示例（JSON）

```json
{
    "matcher": {
        "block_scanner": {
            "UserAgent": ["*nikto*", "*sqlmap*", "*nmap*"],
            "URI": ["/*"]
        },
        "api_only": {
            "URI": ["/api/*"]
        },
        "admin_panel": {
            "IP": ["10.0.0.0/8"],
            "URI": ["/admin/*"]
        }
    }
}
```

---

## 规则组（Rule Group）

VeryNginx v2 使用规则组来组织不同类型的规则。每个规则组对应一个插件，规则按数组顺序依次匹配，**一旦命中即短路**（不再继续匹配同组后续规则）。

### 通用规则结构

```json
{
    "rule": {
        "<规则组名>": [
            {
                "enable": true,
                "matcher": "matcher_name",
                "action": "block",
                "code": 403,
                "response": "forbidden_json"
            }
        ]
    }
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `enable` | bool | 是否启用该规则 |
| `matcher` | string/object | 引用的 Matcher 名称，或内联 Matcher 定义 |
| `action` | string | 动作类型 |
| `code` | number | HTTP 状态码（可选） |
| `response` | string | 引用的响应模板名称（可选） |
| `to_uri` | string | 重定向/重写目标 URI（可选） |
| `upstream` | string | 上游服务器名称（仅 proxy 动作） |

### 过滤器组（filter）—— WAF

用于拦截恶意请求。预置了常见的 WAF 规则，可防止 SQL 注入、路径遍历、扫描器等。

```json
{
    "rule": {
        "filter": [
            {
                "enable": true,
                "matcher": "block_sql_injection",
                "action": "block",
                "code": 403,
                "response": "forbidden_json"
            }
        ]
    }
}
```

支持的动作：`block`, `accept`, `response`

### 频率限制组（frequency_limit）

限制客户端在指定时间窗口内的请求次数。

```json
{
    "rule": {
        "frequency_limit": [
            {
                "enable": true,
                "matcher": "api_public",
                "action": "block",
                "code": 429,
                "response": "rate_limit_exceeded",
                "rate": "100/m"
            }
        ]
    }
}
```

`rate` 格式：`<数量>/<时间单位>`，支持 `s`（秒）、`m`（分）、`h`（时）。例如 `10/m` 表示每分钟最多 10 次。

### 浏览器验证组（browser_verify）

通过 Set-Cookie + JavaScript 验证客户端是否为真实浏览器，用于防御 CC 攻击和机器人流量。

```json
{
    "rule": {
        "browser_verify": [
            {
                "enable": true,
                "matcher": "sensitive_path",
                "action": "browser_verify"
            }
        ]
    }
}
```

> 注意：此功能会拦截搜索引擎爬虫，建议仅在被攻击时开启，或针对特定敏感路径启用。

### 反向代理组（proxy_pass）

将请求代理到后端上游服务器。

```json
{
    "rule": {
        "proxy_pass": [
            {
                "enable": true,
                "matcher": "api_traffic",
                "action": "proxy",
                "upstream": "my_backend"
            }
        ]
    }
}
```

必须同时配置对应的 `backend_upstream`（见下文）。

### 静态文件组（static_file）

使用本地文件系统处理请求。

```json
{
    "rule": {
        "static_file": [
            {
                "enable": true,
                "matcher": "static_assets",
                "action": "static",
                "root": "/var/www/html",
                "path": "$vn_uri",
                "expires": "7d"
            }
        ]
    }
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `root` | string | 文件根目录 |
| `path` | string | 文件路径（支持 Nginx 变量，如 `$vn_uri`） |
| `expires` | string | 缓存过期时间（如 `7d`, `1h`, `epoch`） |

### 重定向组（redirect）

URL 重定向。

```json
{
    "rule": {
        "redirect": [
            {
                "enable": true,
                "matcher": "old_path",
                "action": "redirect",
                "to_uri": "https://new.example.com$vn_uri",
                "code": 301
            }
        ]
    }
}
```

`code` 支持 `301`（永久）和 `302`（临时，默认）。

### URI 重写组（uri_rewrite）

内部 URI 重写（对客户端透明）。

```json
{
    "rule": {
        "uri_rewrite": [
            {
                "enable": true,
                "matcher": "versioned_api",
                "action": "rewrite",
                "to_uri": "/api/v2$vn_uri"
            }
        ]
    }
}
```

### 协议锁定组（scheme_lock）

强制使用 HTTP 或 HTTPS。

```json
{
    "rule": {
        "scheme_lock": [
            {
                "enable": true,
                "matcher": "all_traffic",
                "action": "redirect",
                "scheme": "https",
                "code": 302
            }
        ]
    }
}
```

---

## 后端上游配置（backend_upstream）

反向代理的目标服务器定义。

```json
{
    "backend_upstream": {
        "my_backend": {
            "nodes": [
                {"host": "192.168.1.10", "port": 8080, "weight": 10},
                {"host": "192.168.1.11", "port": 8080, "weight": 5}
            ],
            "health_check": {
                "path": "/health",
                "interval": 5,
                "timeout": 3,
                "unhealthy_count": 3,
                "healthy_count": 2
            },
            "tls": {
                "enable": false,
                "sni": "backend.example.com",
                "verify": false
            },
            "timeout": {
                "connect": 5,
                "read": 60,
                "send": 60
            },
            "method": "round_robin",
            "dns_ttl": 60
        }
    }
}
```

| 字段 | 说明 |
|---|---|
| `nodes` | 上游节点列表，支持 `host:port` 和权重 |
| `health_check.path` | 健康检查探测路径 |
| `health_check.interval` | 探测间隔（秒） |
| `tls.enable` | 是否启用 HTTPS 代理到上游 |
| `tls.verify` | 是否验证上游证书（需配置 CA） |
| `timeout` | 代理超时（秒） |
| `method` | 负载均衡策略：`round_robin`（默认） |
| `dns_ttl` | DNS 解析缓存 TTL（秒，0 表示禁用缓存） |

### 健康检查

VeryNginx 会定期对每个上游节点发送 HTTP 请求进行健康检查：

- 连续 `unhealthy_count` 次失败 → 节点标记为不可用（从负载均衡中移除）
- 连续 `healthy_count` 次成功 → 节点恢复可用
- 健康检查支持 HTTPS（`tls.enable: true`）

### DNS 解析

- 启动时解析 `nodes` 中的域名到 IP
- 结果缓存在共享内存中，按 `dns_ttl` 过期
- 支持多个 A 记录，自动轮询

---

## 响应模板

预定义响应内容，可在规则中通过 `response` 字段引用。

```json
{
    "response": {
        "forbidden_json": {
            "code": 403,
            "content_type": "application/json",
            "body": "{\"error\":\"forbidden\"}"
        },
        "maintenance_html": {
            "code": 503,
            "content_type": "text/html; charset=utf-8",
            "body": "<html><body><h1>维护中</h1></body></html>"
        }
    }
}
```

---

## 插件系统

插件是 VeryNginx v2 的核心抽象。每个规则组关联一个插件，插件可以独立启用、调整优先级、标记为 critical。

### 内置插件

| 插件名 | 默认优先级 | 默认启用 | 默认 critical | 功能 |
|---|---|---|---|---|
| filter | 100 | 是 | 是 | WAF 请求过滤 |
| frequency_limit | 200 | 是 | 是 | 频率限制 |
| browser_verify | 300 | 否 | 是 | 浏览器验证 |
| router | 400 | 是 | 否 | 请求路由分发 |
| proxy_pass | 500 | 是 | 是 | 反向代理 |
| static_file | 600 | 是 | 否 | 静态文件服务 |
| summary | 900 | 是 | 否 | 访问统计 |

### 配置

```json
{
    "plugin": {
        "filter":          { "enable": true,  "priority": 100, "critical": true  },
        "browser_verify":  { "enable": false, "priority": 300, "critical": true  },
        "summary":         { "enable": true,  "priority": 900, "critical": false }
    }
}
```

- `enable`：是否启用该插件
- `priority`：执行顺序（数值越小越先执行）
- `critical`：如果设为 `true`，插件执行出错时将直接返回 503，停止处理请求

---

## 统计与监控

### 请求统计

VeryNginx 按 URI 统计请求数据，支持多个时间窗口：

| 窗口 | 说明 |
|---|---|
| 1m | 最近 1 分钟 |
| 5m | 最近 5 分钟 |
| 1h | 最近 1 小时 |
| all | 累计总量 |

每个 URI 记录：总请求数、各状态码次数、总流量、平均流量、总响应时间、平均响应时间。

### Prometheus 指标

启用后可通过 `GET /verynginx/metrics` 获取 Prometheus 格式的指标：

```
# HELP verynginx_requests_total Total requests
# TYPE verynginx_requests_total counter
verynginx_requests_total{status="200"} 1234
verynginx_requests_total{status="404"} 56

# HELP verynginx_request_duration_seconds Request duration
# TYPE verynginx_request_duration_seconds histogram
verynginx_request_duration_seconds_bucket{le="0.1"} 1000
# ...
```

### 查看统计

管理面板 → 统计页面，可按 URI、请求数、响应时间等排序。

---

## 安全配置

### 管理员认证

VeryNginx v2 支持会话（session）认证策略。密码使用 PBKDF2-HMAC-SHA256 加盐哈希存储，并可选升级到 bcrypt 或 argon2（需安装对应的 Lua 库）。

密码哈希生成：
```bash
python install.py hash-password your_secure_password
```

### CSRF 保护

默认启用。所有配置变更请求都需要携带 CSRF token。

### 会话

- 会话默认 TTL：3600 秒（1 小时）
- Cookie 前缀：`verynginx`
- 可在 `config.json` 中调整 `security.session_ttl`

### 请求体限制

```json
{
    "body": {
        "max_size": 1048576,
        "max_args": 100,
        "on_error": "fail_closed"
    }
}
```

- `max_size`：允许的最大请求体大小（字节）
- `max_args`：最大参数数量
- `on_error`：当请求体解析失败时的行为
  - `fail_closed`：阻止请求（默认）
  - `match`：继续匹配
  - `skip`：跳过正文检查

---

## 配置管理

### 热更新

通过 Web 面板保存配置后，会执行以下流程：

1. 获得保存锁（防止并发写入）
2. 验证配置完整性
3. 规范化默认值
4. 自动备份当前配置到 `configs/backups/`（保留最近 10 份）
5. 原子写入 `config.json.tmp` → `config.json`
6. 切换运行时快照（零停机）
7. 更新共享内存中的配置哈希

**其他 worker 进程** 在 rewrite 阶段通过 MD5 哈希比对检测到变更后自动加载新配置。

### 手动编辑

也可以直接编辑 `/opt/verynginx/verynginx/configs/config.json`，然后：

```bash
kill -HUP $(cat /opt/verynginx/openresty/nginx/logs/nginx.pid)
# 或
/opt/verynginx/openresty/nginx/sbin/nginx -s reload
```

### 恢复出厂设置

删除 `config.json`，VeryNginx 会使用内置默认值启动：

```bash
rm /opt/verynginx/verynginx/configs/config.json
/opt/verynginx/openresty/nginx/sbin/nginx -s reload
```

### 回滚

备份文件保存在 `configs/backups/config.<timestamp>.json`，可通过 API 或手动复制进行回滚。

---

## 常见问题

### 如何让 Nginx 同时代理普通请求和提供静态文件？

只需在 `rule` 中添加两个规则组的规则。规则按优先级顺序执行（filter → frequency_limit → browser_verify → router → proxy_pass → static_file → summary）。Router 插件（priority 400）负责根据 `rule.router` 中的规则进行分发。

### 为什么配置保存后没有生效？

VeryNginx 的配置保存后**立即生效**，无需重启 Nginx。如果是跨 worker 进程，新的配置通过共享内存哈希同步，最长延迟为一个请求的 rewrite 阶段。

### 如何调试规则是否生效？

检查 Nginx 错误日志（`/opt/verynginx/openresty/nginx/logs/error.log`），VeryNginx 的插件错误会记录到日志中。

### 上游节点不健康，如何排查？

1. 确认健康检查路径（`health_check.path`）在目标服务器上可访问
2. 检查网络连通性：`curl http://<node>:<port>/<health_path>`
3. 检查 nginx 错误日志中是否有连接超时或拒绝的记录
4. 如果是 HTTPS 上游，确认 `tls.enable: true` 已配置，证书有效

### 如何保护管理面板？

1. 修改默认管理员用户名和密码
2. 设置 `dashboard_host` 限制特定域名访问
3. 使用 `scheme_lock` 规则强制 HTTPS
4. 在 Nginx 层面增加 IP 白名单限制 `/verynginx/` 路径
5. 修改 `base_uri`（如 `/nvx7k2`）避免被自动化扫描器探测

### Dashboard 功能概览

| 标签页 | 功能 |
|--------|------|
| Overview | 系统概览：连接数、请求速率、WAF 命中、上游健康、共享字典使用率 |
| Status | Nginx 连接状态趋势图 |
| Config | 配置管理：匹配器、规则、上游、响应模板、插件、IP 频率限制、系统设置、原始 JSON |
| Stats | 请求统计：按 URI 统计、Top 路径 |
| WAF | WAF 规则管理：规则列表、暂存审批流、分析（效果评级 + 死规则）、时间线、命中记录、规则测试器 |
| Frequency | 频率限制：规则管理 + 活跃计数器 |
| Reputation | IP 信誉：被标记 IP、白名单、分数查询、持久化 |
| Audit | 操作审计：按用户/操作类型/时间筛选 |

### WAF 规则分析

**效果评级**：
| 评级 | 含义 |
|------|------|
| A+ | 纯 block 规则，有效拦截 |
| A | Challenge 规则通过率低（<50%），说明拦截有效 |
| B | Challenge 规则通过率中等（50-80%） |
| C | Challenge 规则通过率高（>80%），可能存在误伤 |
| N/A | 无命中数据 |

**攻击时间线**：堆叠柱状图按攻击类别（SQLi=红色、XSS=橙色、扫描器=蓝色等）分色展示，时间范围可选 1-24 小时，桶粒度 1-30 分钟。

**命中详情**：点击任意命中记录可查看完整请求上下文（UA、URI、Query String、Body 片段、Headers、IP 信誉分数/标记状态/白名单状态、同 IP 其他命中）。

### 频率管理

限流规则支持按 IP / URI / User / Host 维度，可配置限制窗口（秒）和最大命中次数。Dashboard 显示当前活跃的计数器 Top 50。

### 会话安全

- 默认会话 TTL：**8 小时**（`config.json` → `security.session_ttl`）
- 账户锁定：5 次连续登录失败后锁定 15 分钟
- 登录速率限制：IP 级 30 次/分钟，用户名级 5 次/分钟
- 管理员操作连续失败 5 次后账户自动锁定

### 性能建议

- `lua_code_cache on`（默认）—— 生产环境必须开启
- 共享字典大小根据实际流量调整（`in_http_block.conf` 中的 `lua_shared_dict`）
- `max_uri_keys` 限制统计追踪的 URI 数量，避免内存溢出
- 开启 `gzip` 压缩减少管理面板响应体积
- `statistics` 共享字典 20MB 默认足够千 QPS 级别使用

---

## 参考

- [INSTALL_zh.md](INSTALL_zh.md) — 安装手册
- [DESIGN_V2.md](DESIGN_V2.md) — v2 架构设计
- [IP 信誉调优](IP_REPUTATION_TUNING_GUIDE.md) — 生产环境阈值配置与误报排查
- [WAF API 参考](WAF_API.md) — 规则管理 REST API
- [VeryNginx Issues](https://github.com/nengfeng/VeryNginx/issues)
