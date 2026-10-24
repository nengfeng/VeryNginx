# VeryNginx v2

一个基于 Nginx + Lua 构建的强大、可扩展的 WAF（Web 应用防火墙）、反向代理和请求管理引擎。

[English](readme.md) | [安装手册](docs/INSTALL_zh.md) | [使用手册](docs/USAGE_zh.md) | [架构设计](docs/DESIGN_V2.md)

## v2.3 亮点（2026-10-13）

- **请求体检查全面重做**：`multipart/form-data` 的字段名与字段值都进入 WAF 检查（文件内容跳过），此前修掉三处 P0 级解析器绕过与一个参数名盲区；新增 `body.max_field`（字段长度上限，独立于 `max_size`）、`body.scan_exempt`（URI 豁免、大小写不敏感，如 phpMyAdmin），`body.on_error` 默认改为 `log` 并采用 ModSecurity *ProcessPartial* 前缀扫描——超大 body 既不会被整体读入，也不会静默漏检
- **默认规则集加固 v9 → v17**：新增 ssrf 类别、关闭多类扫描器绕过路径、`vn_scanner_0014` 终于命中 ffuf 的真实默认 UA、管理路径豁免支持 `.php`（`/adminer.php` 等），sqli/xss/ssrf/rce 在三轮外部复评后重做：`UNION(SELECT)`/`UNION DISTINCT` 可命中、恒真式缺口闭合（注释混淆、`LIKE`/`IN`/`BETWEEN`）、教程散文误报大幅收敛、XSS 事件表补全、`javascript:` 改为按代码形态判定、SSRF 覆盖 `user@` 前缀。`vn_rce_0007` 定型为**值锚定 block**（分隔符在值首 + 24 个高危裸调用命令、不做参数形态要求——因此 `data:` URI 与 CSV 不会被拦，而 `; rm file` 照样拦），宽命令表落入 log-only 伴随规则；「值内不许有非 ASCII」这类守卫已被明令禁用——它是万能绕过开关（追加一个高位字节，全部载荷瞬间清零）
- **TLS 指纹改用 JA4，并修掉两条从未真正生效的链路**：旧实现读 `$ssl_client_j3_hash`（vanilla nginx 未编译该模块，恒为 nil），且 filter 插件读的是一个**全仓无人写入**的 `ctx.request.ja3_fingerprint`——所以指纹封禁/挑战与跨 IP 关联告警从未真正触发。现在改为握手期一次性计算 JA4（唯一能看到原始 ClientHello 的阶段），**无需重编 nginx**，且因其对密码套件/扩展排序而免疫 GREASE 随机化。指纹库条目带 **kind**（ja3/ja4/ja4h）与**匹配方式**（exact/family），匹配按 kind 分空间，`tls:`（协商套件串）显式不可匹配，family 匹配取人可读的 section A 前缀，客户端换套件后仍能按家族追踪。`tools/import_ja4db.py` 可把 FoxIO 官方映射表转成候选条目（**默认 log**，与良性客户端共享的哈希整条跳过）
- **出厂差异透明化**：新增漂移接口报告内容/动作/缺失三类差异，面板解释灰度 log 与陈旧动作的来由，并可对单条规则「接受出厂动作」；`restore-defaults` 只按 id 补回缺失的出厂规则，绝不覆盖操作者已设置的动作
- **IP 声誉可观测性**：被标记 IP 带原因、可下钻扣分记录、可选 IP 质量查询，并新增按日持久化的标记日志（保留 48h，写路径封顶——此前它无界增长会在全局索引锁内跑 O(n)，把索引卡住）
- **每主机请求统计**：请求面板支持按主机过滤与聚合
- **面板历史 tab 以撤销语义重做**：回滚可再撤销、删除可按条恢复；出厂漂移提示与逐条接受动作并排呈现
- **运维修复**：GeoIP 校验与镜像下载报告、lua-resty-http 0.18.0、安装器升级时保留运行时配置、全新安装自动配置 Cloudflare 真实客户端 IP（`http_realip_module` + 官方网段）、`upgrade.sh` 会重新注入 TLS 指纹钩子（否则升级后 JA4 代码在、钩子不在，链路又空转）
- **常驻门禁**：每条出厂规则都配 PCRE 正负样本回归测试集（`test/v2/factory_rules_battery.py`，312 项、逐命令族覆盖、真机 PCRE 双引擎对照），vendor 的 JA4 实现以 FoxIO 官方向量钉死（`test/v2/ja4_golden.lua`），另有 luacheck 0/0（103 文件）、spec 353、phase0 374 与面板绑定门禁

---

## v2.2 亮点（2026-09-06）

- **安全审计清零（35 项发现全部闭环）**：会话/密码常量时间比较重写（旧代数恒等式可按约 1/20,000 概率伪造 admin 会话）；代理上游 TLS 校验开启（自签后端需显式指定 CA）；`configs/` 权限加固——`session_secret` 不再全局可读；代理链路崩溃与内部重定向循环修复（该链路此前从未被端到端执行过）；请求期 JSON 加固——`POST /config` 畸形 body 返回 400 而非 500
- **契约收紧**：proxy 规则必须声明 `action`；白名单 ≤/8 的 CIDR 拒收（会中和内核拦截）；频率规则 id 校验；Composite（AND/OR/NOT）matcher 递归校验；systemd helper 修复（reconcile 守卫、conn deadline、flush 范围、allow-prefix 下限）
- **升级信任模型**：`upgrade.sh` 固定部署 commit（锚定于安装时、经已验证 checkout 自更新）、报告对分支的落后量、升级时重建 firewall helper，并封禁了让分支写者控制 pin 的 `curl | bash` 流程
- **供应链**：OpenResty/Go 下载校验和固定；基础镜像迁移 bookworm（bullseye EOL）；安装器权限修复
- **质量门禁**：luacheck 覆盖全部 Lua（含生命周期入口文件），busted spec + phase0 套件与 Go helper 测试进入 CI（216 spec / 329 phase0 用例、10 个 Go 测试文件全绿），安装期 SRI 自检，面板版本元数据修复（不再显示 dev）
- **启动可靠性**：webhook DNS 校验的 init 阶段守卫（域形态 webhook 不再 brick nginx 启动）；静态文件字节保真输出（`ngx.print` 替代带换行的 `ngx.say`）
- **安装器加固**：cosocket DNS 的 resolver 注入、出站 TLS 的 `lua_ssl_trusted_certificate`、SRI 钉值 vs 实际服务内容漂移比对、重装盲区清理、自检 000 端口归因
- **安全**：SSRF 对 IPv6 括号/映射字形的防护、空 `session_secret` fail-closed 覆盖、审计遗留清偿批次
- **面板稳定性**：`asList` 消毒全量收口 + 「模板绑定 == 导出集合」静态门禁；表格工具 reactive 修复；模块改名规避 uBlock（`vn-iploc.js`）
- **WAF 规则测试器**：表单化测试（免手写 JSON）、一键载入现有规则、粘贴访问日志自动生成用例
- **测试**：spec 199 + phase0 317 全绿；新增回归套件（init 阶段 webhook、字节保真、消毒契约）

---

## v2.1 亮点（2026-08-16）

- **性能优化**：Per-rule WAF 统计走索引（告别 `get_keys` 200 键上限），`is_v2_active()` 与 `is_whitelisted()` generation 读取缓存化，IP 信誉收集走 score_cache 快路径
- **竞态修复**：`waf_rule_stats` 与 `metrics` 索引原子更新（token 验证锁），`flush_hit_stats` 定时器仅 worker 0 运行（防双计/head 回退）
- **安全加固**：`/config` 与 `/config/export` 脱敏 `session_secret`；config save 自动从哨兵值恢复真实密钥；SSRF 守卫 IPv6 私有地址检测大小写不敏感
- **内核拦截健壮性**：Per-worker IPC 互斥锁带 token 所有权，`close_socket_no_backoff` 护卫 scope binding，generation bump 置于 config save 锁内
- **可观测改进**：Prometheus 导出纯索引（无 `get_keys` 兜底）；共享字典告警覆盖 `metrics_labeled`
- **Schema 完整性**：频率限制模板 CIDR 拒绝（matcher 无 CIDR 语义）；`config.whitelist` 保存时逐条校验 IP/CIDR 格式

---

## 功能特性

### Web 应用防火墙（WAF）

- **插件化架构** — filter、frequency_limit、browser_verify、proxy_pass、static_file、router、summary 七种内置插件
- **10 种匹配器** — IP（CIDR）、Host、URI、UserAgent、Referer、Args、Header、Cookie、Method、Composite（组合）
- **8 个规则组** — filter（过滤）、frequency_limit（频率限制）、browser_verify（浏览器验证）、proxy_pass（反向代理）、static_file（静态文件）、redirect（重定向）、uri_rewrite（URI 重写）、scheme_lock（协议锁定）
- **预置 WAF 规则** — 26 条出厂规则，覆盖 sqli / xss / rce / lfi / path_traversal / ssrf / scanner / bot / brute / spam / crlf / deserialization，以可编辑 JSON 交付，并配面板的出厂差异视图
- **浏览器验证** — Cookie + JavaScript 挑战，防御 CC 攻击和机器人流量
- **频率限制** — 支持按 IP、URI、自定义键的精细化限流
- **规则审批流** — 规则修改可先暂存为 "pending"，确认后再生效
- **规则效果评分** — 根据 challenge 通过率和命中数自动评级（A+/A/B/C/D）
- **死规则检测** — 30 天内零命中的规则自动标灰，提示清理
- **攻击时间线** — 堆叠柱状图，按攻击类别分色展示攻击趋势
- **命中详情钻取** — 点击任意命中记录查看完整请求上下文（UA、Headers、Body、IP 信誉）
- **规则测试历史** — 自动保存最近 20 次测试，方便对比调试
- **内置规则测试器** — 请求样本 + 匹配结果，即时验证规则
- **IP 信誉引擎** — 基于 WAF 阻断/Challenge/404 信号评分，自动标记、白名单、Challenge 流程，标记带原因并有按日标记日志
- **TLS 指纹（JA4）** — 通过 TLS ClientHello 指纹识别客户端，在握手阶段（`ssl_client_hello_by_lua*`）计算，**无需重编 nginx**，对 GREASE 随机化免疫；指纹库按 kind（`ja3`/`ja4`/`ja4h`）分空间，支持精确或家族（section A 前缀）匹配，协商套件降级串只记录不匹配；JA4H（HTTP 层）可通过 `fingerprints.ja4.http_enable` 开启

### 反向代理

- **动态上游** — 通过 Web 面板随时增删节点，无需重载
- **健康检查** — 定期 HTTP/HTTPS 探测，自动摘除不健康节点
- **DNS 缓存** — 启动时解析域名，按 TTL 缓存，支持多个 A 记录轮询
- **负载均衡** — 加权轮询，自动剔除故障节点
- **WebSocket 支持** — 自动处理 Upgrade/Connection 头传递
- **上游 TLS/SSL** — SNI、证书验证全面支持

### 内核 IP 拦截（Kernel IP Blocking）

- **WAF → 内核晋升** — 确认恶意 IP（扫描器/CC）通过 Go Helper 从 WAF 晋升到 Linux nftables 内核防火墙
- **四组逻辑集合** — `scanner_drop`、`cc_drop`、`manual_drop`、`allow`，原子 nft 事务写入
- **特权 Helper** — Go 静态二进制 + Unix Domain Socket IPC（Protocol v1）；仅需 `CAP_NET_ADMIN`（无需 root）
- **金丝雀部署** — 初始短 TTL（扫描器 60s / CC 30s），高置信信号自动升级到完整 TTL
- **紧急操作** — 暂停/恢复晋升、清空自动集合、手动 IP 封禁/解封
- **Fail-open 设计** — 任何 Helper 故障不影响现有 Lua WAF
- **Dashboard + API** — 完整管理面板和 10 个 REST 接口（`/kernel-blocking/status`、`/entries`、`/candidates`、`/promote`、`/clear`、`/pause`、`/flush-auto`、`/reconcile`、`/bucket-history`、`/diff`）
- **白名单自动同步** — 静态 + 自动白名单通过 generation-qualified 缓存推送到 Helper

### 管理

- **Web 管理面板** — 通过 `/verynginx/index.html` 完成所有配置（`base_uri` 可自定义）
- **暗黑模式** — 内置深色主题，自动跟随系统偏好，localStorage 记忆
- **热更新** — 配置保存后立即生效（零 I/O MD5 哈希比对）
- **原子写入** — `tmp + rename` 策略，自动备份（保留最近 10 份）
- **Prometheus 指标** — `/verynginx/metrics` 端点（per-rule 命中/拦截/Challenge、插件耗时、IP 信誉）。**持久化审计后已强制鉴权**——抓取时需带面板会话 Cookie 或走内网通道
- **请求统计** — 按 URI 细分，支持 1 分钟 / 5 分钟 / 1 小时 / 全部 四个时间窗口，可按主机过滤
- **审计日志** — 环形缓冲区（1000 条），支持按用户、操作类型、时间范围搜索
- **告警引擎** — Webhook 通知：命中率飙升、误报率变化、未知攻击模式、TLS 指纹跨 IP 关联（分布式扫描器识别）
- **频率限制管理** — 独立 Dashboard 页面管理限流规则和活跃计数器

### 安全

- **会话认证** — PBKDF2-HMAC-SHA256 密码哈希（可选升级到 bcrypt 或 argon2），默认 8 小时过期
- **CSRF 保护** — 默认开启，覆盖所有配置接口
- **请求体限制** — 可配置大小上限、字段长度上限、参数数量上限、URI 豁免（`body.scan_exempt`，大小写不敏感）与异常策略（fail-closed / match / skip / log，超大 body 采用 ProcessPartial 前缀扫描）
- **账户锁定** — 5 次登录失败后锁定 15 分钟
- **登录速率限制** — IP 级（30次/分钟）+ 用户名级（5次/分钟）
- **审计日志筛选** — 按用户、操作类型、时间范围搜索，便于安全排查
- **SSRF 防护** — Webhook URL 双重校验（仅 HTTPS、禁止内网 IP），存储时 + 运行时双重拦截

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
| [使用手册](docs/USAGE_zh.md) | 匹配器、规则、上游配置、插件系统、统计、安全、Dashboard 功能 |
| [架构设计](docs/DESIGN_V2.md) | v2 设计文档：插件系统、配置管理、请求生命周期 |
| [内核 IP 拦截设计](docs/KERNEL_IP_BLOCKING_DESIGN.md) | 内核层 IP 拦截：晋升策略、nftables 执行、IPC 协议 |
| [内核 IP 拦截实施计划](docs/KERNEL_IP_BLOCKING_IMPL_PLAN.md) | 实施阶段：证据采集、observe、影子同步、金丝雀、安装集成 |
| [IP 信誉调优](docs/IP_REPUTATION_TUNING_GUIDE.md) | 生产调优：阈值推荐、误报排查、pending TTL 协同 |
| [WAF API 参考](docs/WAF_API.md) | 规则管理、测试、统计、分析的 REST API |

---

## 开源协议

[VeryNginx License](LICENSE.txt)
