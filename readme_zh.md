# VeryNginx v2

一个基于 Nginx + Lua 构建的强大、可扩展的 WAF（Web 应用防火墙）、反向代理和请求管理引擎。

[English](readme.md) | [安装手册](docs/INSTALL_zh.md) | [使用手册](docs/USAGE_zh.md) | [架构设计](docs/DESIGN_V2.md)

---

## 功能特性

### Web 应用防火墙（WAF）

- **插件化架构** — filter、frequency_limit、browser_verify、proxy_pass、static_file、router、summary 七种内置插件
- **10 种匹配器** — IP（CIDR）、Host、URI、UserAgent、Referer、Args、Header、Cookie、Method、Composite（组合）
- **8 个规则组** — filter（过滤）、frequency_limit（频率限制）、browser_verify（浏览器验证）、proxy_pass（反向代理）、static_file（静态文件）、redirect（重定向）、uri_rewrite（URI 重写）、scheme_lock（协议锁定）
- **预置 WAF 规则** — SQL 注入、路径遍历、扫描器检测、Git/SVN 泄露
- **浏览器验证** — Cookie + JavaScript 挑战，防御 CC 攻击和机器人流量
- **频率限制** — 支持按 IP、URI、自定义键的精细化限流

### 反向代理

- **动态上游** — 通过 Web 面板随时增删节点，无需重载
- **健康检查** — 定期 HTTP/HTTPS 探测，自动摘除不健康节点
- **DNS 缓存** — 启动时解析域名，按 TTL 缓存，支持多个 A 记录轮询
- **负载均衡** — 加权轮询，自动剔除故障节点
- **WebSocket 支持** — 自动处理 Upgrade/Connection 头传递
- **上游 TLS/SSL** — SNI、证书验证全面支持

### 管理

- **Web 管理面板** — 通过 `/verynginx/index.html` 完成所有配置
- **热更新** — 配置保存后立即生效（零 I/O MD5 哈希比对）
- **原子写入** — `tmp + rename` 策略，自动备份（保留最近 10 份）
- **Prometheus 指标** — `/verynginx/metrics` 端点，方便接入监控系统
- **请求统计** — 按 URI 细分，支持 1 分钟 / 5 分钟 / 1 小时 / 全部 四个时间窗口

### 安全

- **会话认证** — PBKDF2-HMAC-SHA256 密码哈希（可选升级到 bcrypt 或 argon2）
- **CSRF 保护** — 默认开启，覆盖所有配置接口
- **请求体限制** — 可配置大小上限、参数数量上限、异常策略（fail-closed / match / skip）

---

## 快速开始

```bash
# 一键安装（OpenResty + VeryNginx）
python install.py install

# 设置管理员密码
python install.py hash-password your_password

# 启动
/opt/verynginx/openresty/nginx/sbin/nginx
```

访问 `http://<your-server>/verynginx/index.html`

### 使用自己的 Nginx？

VeryNginx v2 也支持标准 **Nginx + lua-nginx-module + lua-resty-core**，无需完整的 OpenResty 发行版。详见[安装手册](docs/INSTALL_zh.md)。

### Docker

```bash
docker build -t verynginx .
docker run -d --name=verynginx -p 8080:80 verynginx
```

---

## 架构概览

```
请求 → rewrite 阶段 → access 阶段 → balancer → proxy_pass → log 阶段
```

1. **rewrite_by_lua** — 热更新检测、请求上下文创建、协议锁定/重定向/重写
2. **access_by_lua** — 插件按优先级执行（filter → frequency_limit → browser_verify → router → proxy_pass → static_file → summary），遇终端动作短路
3. **balancer_by_lua** — 动态上游节点选择，自动排除不健康节点
4. **proxy_pass** — 反向代理，支持 WebSocket、TLS、DNS 解析
5. **log_by_lua** — 统计收集、指标上报

### 配置更新流程

```
面板/API → 验证 → 规范化默认值 → 备份旧配置 → 原子写入 → 激活新快照
```

其他 worker 进程在下一个请求的 rewrite 阶段通过共享内存中的 MD5 哈希（零文件 I/O）检测到变更并自动加载。

---

## 文档

| 文档 | 说明 |
|---|---|
| [安装手册](docs/INSTALL_zh.md) | install.py 一键安装、手动 Nginx 编译、Docker、安装后配置 |
| [使用手册](docs/USAGE_zh.md) | 匹配器、规则、上游配置、插件系统、统计、安全 |
| [架构设计](docs/DESIGN_V2.md) | v2 设计文档：插件系统、配置管理、请求生命周期 |

---

## 开源协议

[VeryNginx License](LICENSE.txt)
