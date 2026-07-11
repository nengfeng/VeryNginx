# VeryNginx 内核层 IP 封禁设计草案

> **版本**: Draft v0.3
>
> **日期**: 2026-07-11
>
> **状态**: 讨论阶段，尚未实现
>
> **适用范围**: 由项目自有 LNMP 脚本部署的 Linux 直连源站；仅支持该脚本声明的最近两个 Debian/Ubuntu 版本；内核执行层仅支持 nftables

---

## 目录

1. [背景与目标](#1-背景与目标)
2. [现有系统边界](#2-现有系统边界)
3. [设计原则](#3-设计原则)
4. [总体架构](#4-总体架构)
5. [集合与状态模型](#5-集合与状态模型)
6. [自动晋升策略](#6-自动晋升策略)
7. [客户端 IP 与网络拓扑](#7-客户端-ip-与网络拓扑)
8. [权限分离与 Helper](#8-权限分离与-helper)
9. [nftables 执行层](#9-nftables-执行层)
10. [一致性、持久化与恢复](#10-一致性持久化与恢复)
11. [配置草案](#11-配置草案)
12. [管理 API 与 Dashboard](#12-管理-api-与-dashboard)
13. [审计与可观测性](#13-审计与可观测性)
14. [失败策略与紧急恢复](#14-失败策略与紧急恢复)
15. [部署模型](#15-部署模型)
16. [测试与验收](#16-测试与验收)
17. [分阶段实施建议](#17-分阶段实施建议)
18. [非目标与能力边界](#18-非目标与能力边界)
19. [待决策事项](#19-待决策事项)

---

## 1. 背景与目标

### 1.1 背景

VeryNginx 当前在 Nginx/OpenResty 请求阶段执行 WAF、IP 声誉、Challenge 和频率限制。即使请求最终被拒绝，它通常已经消耗了部分资源：

- TCP 连接及可能的 conntrack 状态
- TLS 握手
- Nginx 连接和请求对象
- Lua worker 执行时间
- WAF 规则匹配和共享字典访问
- 日志、统计和审计开销

对于已经被高置信确认的扫描器或持续 CC 来源，重复执行完整应用层判断没有必要。可以将这类 IP 从 WAF 层“晋升”到 Linux 内核防火墙集合，后续数据包在到达 Nginx 前直接丢弃。

### 1.2 设计目标

1. **降低重复恶意流量成本**：已确认恶意 IP 的后续数据包不再进入 Nginx/OpenResty。
2. **渐进式封禁**：只有达到独立晋升条件的 IP 才进入内核集合，单次 WAF 命中不能直接触发。
3. **短时、可恢复**：自动封禁默认带 TTL，到期自动解除，人工封禁可使用独立策略。
4. **最小权限**：Nginx worker 不拥有防火墙管理权限，不执行任意 shell 命令。
5. **执行层隔离**：业务层不直接依赖 nftables 命令格式，内部保留固定执行接口用于隔离、mock 和测试，但不提供多后端选择。
6. **可观察、可解释**：能够回答某个 IP 为什么被封、由哪个策略触发、何时到期、内核是否已安装。
7. **故障不影响主服务**：Helper 或防火墙不可用时 fail-open，现有 Lua WAF 继续工作。

### 1.3 成功标准

- 已安装到内核集合的 IP 不再到达 VeryNginx 请求处理链。
- 自动封禁有明确 TTL、白名单保护和最大容量。
- 请求路径中不产生 shell 子进程，不同步等待防火墙操作。
- Helper 重启、Nginx reload 和规则漂移后能够恢复到可解释状态。
- 功能关闭或同步失败时不阻断 Nginx 启动及正常代理。

---

## 2. 现有系统边界

### 2.1 可复用能力

| 现有模块 | 当前能力 | 与本方案的关系 |
|----------|----------|----------------|
| `core/ip_reputation.lua` | 信号累积、评分、flagged、白名单、自动白名单、持久化 | 提供扫描器候选信号，不直接操作防火墙 |
| `plugin/filter/init.lua` | WAF hard block、Challenge、命中记录 | 提供内容型攻击信号 |
| `plugin/frequency_limit/` | 应用层频率限制 | 提供 CC 候选信号 |
| `core/audit.lua` | 管理操作审计 | 记录人工晋升、解除和配置变更 |
| `core/metrics.lua` | 指标输出 | 暴露候选、安装、失败、漂移等指标 |
| `api/controllers/reputation.lua` | 声誉查询、清除、白名单管理 | 后续可扩展内核封禁管理入口 |
| `api/init.lua` | Auth、CSRF、限流、幂等和审计中间件 | 新管理 API 必须复用 |

### 2.2 必须区分的三个概念

1. **WAF block**：本次 HTTP 请求在 Lua 层被拒绝。
2. **IP reputation flagged**：IP 在一段时间内被声誉层标记，仍由 Nginx/Lua 拒绝。
3. **Kernel block**：IP 被安装进内核集合，后续数据包在进入 Nginx 前被丢弃。

从 WAF block 到 kernel block 必须经过独立晋升策略。现有声誉阈值不能直接等同于内核封禁阈值。

### 2.3 当前未实现的能力

以下内容均属于本草案提出的新能力：

- nftables 执行层及自有 table、chain、set
- 特权 Helper 与本地 IPC
- scanner/CC 独立晋升策略
- 内核集合状态同步和漂移修复
- 内核封禁管理 API、Dashboard 和指标
- Docker 宿主机侧执行模式

---

## 3. 设计原则

### 3.1 默认安全

- 功能默认关闭。
- 首次启用默认进入 `observe` 模式，只生成候选，不写内核。
- 自动封禁必须有 TTL。
- 自动封禁不聚合 CIDR，尤其不自动封禁 IPv6 `/64`。
- 现有 `ip_reputation.whitelist`、运行时自动白名单和可信基础设施优先于自动封禁。
- 无法确认真实网络源 IP 时禁止自动晋升。

### 3.2 请求路径零阻塞

请求处理仅执行有界的 shared dict 证据计数、marker 写入和候选索引写入，不执行策略全量评估、期望状态持久化或 Helper 通信。请求阶段不执行以下操作：

- `os.execute`
- `io.popen`
- `nft` 命令
- 同步 Unix Socket 请求
- 防火墙状态全量读取或 reconciliation

候选事件由 worker 0 定时调度器评估并批量交给 Helper。唯一例外是白名单变更后的高优先级 allow 刷新，它可以由当前请求 worker 使用一次性 `ngx.timer.at(0, ...)` 异步发送，但 API 请求本身不得等待 IPC。

### 3.3 最小权限和固定边界

- Nginx worker 继续使用普通 `nginx` 用户。
- Helper 只获得管理自有集合所需的能力。
- Helper 只接受固定操作和结构化参数，不接受任意命令字符串。
- VeryNginx 只管理带固定前缀的 table、chain 和 set。
- 不修改或清空用户已有的防火墙规则。
- 首期只处理明确配置的 Web 监听地址、TCP 端口和本机入站流量，不影响 SSH、其他服务或经过本机转发的流量。

权限隔离只能限制 worker 对系统防火墙的操作范围，不能把已被攻陷的 worker 变成可信决策源。Helper 仍需独立检查现有 `ip_reputation.whitelist` 的规范化快照、内建保留地址、作用域、TTL、容量和晋升速率，即使请求来自合法 Socket 对端也不能无条件执行。

### 3.4 幂等与可回滚

- 重复 `add` 不报错，只刷新或限制 TTL。
- 删除不存在的 IP 视为成功。
- 关闭“新增晋升”和清空“已有内核集合”是两个独立动作。
- nftables 规则结构或策略升级必须支持 observe/shadow 阶段。

---

## 4. 总体架构

### 4.1 数据流

```text
                         管理 API / Dashboard
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────┐
│                    VeryNginx 控制面                       │
│  WAF 命中 ─┐                                             │
│  声誉评分 ─┼─> Promotion Policy ─> Desired Block State   │
│  频率限制 ─┘        │                    │                │
│                     └─ observe/audit      │ batch events  │
└───────────────────────────────────────────┼───────────────┘
                                            │ Unix Socket
                                            ▼
┌──────────────────────────────────────────────────────────┐
│                 Privileged Firewall Helper               │
│  参数校验 -> 白名单保护 -> 去重/限额 -> Nft Executor     │
│                       │                                  │
│                 Reconciler / Health                      │
└───────────────────────┼──────────────────────────────────┘
                        │
                        ▼
          nftables table inet verynginx
                        │
                        ▼
               Linux kernel DROP sets
```

### 4.2 请求路径

```text
网络数据包
  │
  ▼
VeryNginx 自有内核链
  ├─ 命中白名单：RETURN，继续系统原有规则
  ├─ 命中 manual_drop：DROP
  ├─ 命中 scanner_drop：DROP
  ├─ 命中 cc_drop：DROP
  └─ 未命中：RETURN
          │
          ▼
Nginx/OpenResty
  │
  ├─ WAF filter
  ├─ IP reputation
  ├─ frequency_limit
  └─ proxy/static/response
```

白名单命中使用 `RETURN` 而不是全局 `ACCEPT`，避免绕过操作系统已有的其他安全规则。`allow` 集合不是新增的用户配置来源，而是现有 `ip_reputation.whitelist` 及运行时自动白名单在执行面的派生快照。

自有链必须先限制到配置的保护作用域，例如目标为本机、协议为 TCP、目标端口为 VeryNginx 实际监听端口。默认不对 UDP、SSH、同机其他应用或转发流量执行这些集合的 DROP。若未来支持主机全局封禁，应作为独立的显式模式，而不是自动策略默认行为。

### 4.3 组件职责

#### Promotion Policy

- 从有界候选索引读取由 WAF、声誉和频率限制信号源写入的证据。
- 根据 scanner/CC 独立策略产生候选和晋升决定。
- 复用现有 `ip_reputation.whitelist` 和自动白名单，执行地址合法性和拓扑安全检查。
- 生成原因、TTL、策略版本和证据摘要。
- 不作为普通 access 插件运行，不改变 `ctx.action_result`，不直接写防火墙。

#### Firewall Helper

- 按 IPC Protocol v1 验证请求、对端身份、generation 和幂等 request ID。
- 管理固定名称的集合和链。
- 执行固定的 probe、ensure_base、add、delete、list、health、reconcile、flush_owned 和 replace_allow_snapshot 操作。
- 控制最大条目数、TTL 范围和允许的地址族。
- 返回结构化结果，不返回原始命令输出。

#### Reconciler

- 比较期望状态与实际内核状态。
- 补装缺失条目，移除已过期或不再期望的条目。
- 检测链或集合被外部删除、规则顺序变化和容量异常。
- 在后台运行，不阻塞请求。

### 4.4 Promotion 执行阶段与插件边界

Promotion 使用三阶段模型，不改变现有插件顺序：

```text
filter(priority 100)
  -> frequency_limit(priority 200)
  -> browser_verify(priority 300)
```

现有 `block` 和 `challenge` 都是 terminal action。某个阶段产生 terminal action 后，后续插件不会执行；Promotion 不得合成原请求中没有发生的后续信号。

#### 阶段 A：请求路径只记录证据

- `filter` 仅在启用的 WAF 规则以 `action="block"` 实际命中并产生现有 `waf_block` 信号后，同步写入 scanner block 证据，然后设置 terminal action。
- `frequency_limit` 在原始计数第一次从 `limit` 变为 `limit + 1` 时写入 CC violation marker，然后执行该规则现有的应用层 block 响应。
- Challenge 证据仍由现有 WAF/Challenge 流程产生。频率插件不调用后续 `browser_verify`，Promotion 也不为 CC 人工制造 `challenge_fail`。
- 证据写入只允许原子计数、固定大小 marker 和有界候选索引操作，不执行 IPC、JSON 网络通信、磁盘 I/O 或全量扫描。

#### 阶段 B：worker 0 后台评估与派发

- `core.init` 的 worker 0 调度器按 `batch_interval` 调用 Promotion Policy，消费有界候选索引并读取当前已规范化配置。
- 评估顺序为：证据有效性、loose/strict 结果、白名单和拓扑安全门、集合重叠、容量、自动晋升速率限制、期望状态转换。
- observe 模式只记录 `would_promote`、`would_rate_limit` 和拒绝原因，不创建可安装的期望状态，不发送 mutating IPC。
- enforce 模式只有在全部安全门通过后才原子创建或延长期望状态，并将 Protocol v1 请求放入有界 dispatch 队列。
- 同一候选按 `(policy, canonical_ip, evidence_generation, policy_version)` 幂等评估。队列由 shared dict 中的有界索引承载，不能使用请求 worker 本地 Lua table。

#### 阶段 C：Helper 验证与安装

- Helper 独立验证白名单 generation、作用域、地址、TTL、容量、所有权和自动晋升硬限额。
- IPC 响应成功只表示对应操作结果已确定；只有 nftables transaction 成功后控制面才能把条目标记为 `installed`。
- 可重试错误保留为 `dispatch_pending` 或 `degraded`，由有界重试和 reconciliation 处理。永久验证错误回退到 candidate/rejected 并记录固定原因。

---

## 5. 集合与状态模型

### 5.1 建议集合

| 逻辑集合 | 来源 | 默认生命周期建议 | 说明 |
|----------|------|------------------|------|
| `scanner_drop` | 高置信 WAF/声誉晋升 | 初始复用 `ip_reputation.flag_duration`（当前默认 600 秒），重复晋升可分级延长 | 处理漏洞扫描、目录扫描、RCE/SQLi 重复探测 |
| `cc_drop` | 持续频率违规；策略启用时可额外要求同一证据期内已有 Challenge 失败 | 1 至 10 分钟 | 短 TTL，降低 NAT/CGNAT 误封影响 |
| `manual_drop` | 管理员操作 | 明确 TTL 或永久 | 与自动策略隔离 |
| `allow` | 现有 `ip_reputation.whitelist`、运行时自动白名单 | 由现有白名单状态派生 | 在 VeryNginx 自有链中优先 RETURN，不引入第二套用户配置 |

`scanner_drop` 的初始 TTL 直接复用现有声誉层配置，避免同一风险状态出现两套基础生命周期。CC、重复晋升上限和人工封禁 TTL 仍属于待 observe 数据验证的新策略。

白名单优先级高于所有 VeryNginx 自有 DROP 集合，包括 `manual_drop`。普通人工封禁不能绕过白名单；如果新白名单覆盖已有人工封禁，该条人工期望状态标记为 `suppressed_by_allow` 并从内核 DROP 集合移除。白名单删除后不自动恢复该人工封禁，必须由管理员显式重新启用。若未来需要强制覆盖白名单，应设计独立的 break-glass 流程，不能复用普通 `manual_drop`。

#### Scanner 与 CC 重叠

同一 IP 只安装到一个自动 DROP 集合，避免 TTL、解除操作、原因和指标产生歧义。自动集合优先级为：

```text
scanner_drop > cc_drop
```

- 两个策略同时满足时安装到 `scanner_drop`。
- 已处于 `cc_drop` 的 IP 如果已有证据同时满足 scanner，则原子升级到 `scanner_drop`，不能缩短现有 TTL。
- 如果 CC 先触发而 scanner 尚未满足，内核 DROP 后流量不再到达 Nginx，scanner 证据停止增长是预期行为；此时 `cc_drop` 已经完成保护，不要求继续晋升。
- `cc_drop` 到期后若攻击恢复，新的应用层证据可再次触发 CC 或 scanner。
- `manual_drop` 保持独立审计语义，但执行时仍受 `allow` 最高优先级约束。

### 5.2 IPv4 与 IPv6

逻辑集合在 nftables 中至少拆分为：

```text
scanner_drop_v4
scanner_drop_v6
cc_drop_v4
cc_drop_v6
manual_drop_v4
manual_drop_v6
allow_v4
allow_v6
```

要求：

- IP 入库前规范化。
- IPv4-mapped IPv6 地址转换规则必须统一。
- IPv4 和 IPv6 集合独立管理，单一地址族配置或数据异常不能破坏另一地址族。
- IPv6 前缀聚合默认关闭。
- 当前 IP 声誉 CIDR 匹配能力以 IPv4 为主，不能假设已有完整 IPv6 白名单能力。

### 5.3 生命周期

```text
observed
   │ 达到候选条件
   ▼
candidate
   ├─ 安全门拒绝 -> rejected
   ├─ 自动晋升桶无 token -> rate_limited -> 保持 candidate
   │ 达到晋升条件，且通过全部安全检查
   ▼
promoted
   │ 进入有界派发队列
   ▼
dispatch_pending
   │ Helper 完成 nftables transaction
   ▼
installed
   ├─ TTL 到期 -> expired
   ├─ 管理员解除 -> cleared
   ├─ 白名单覆盖 -> cleared
   └─ 同步失败/规则漂移 -> degraded -> reconcile
```

每个状态至少包含：

```json
{
  "ip": "203.0.113.10",
  "family": "ipv4",
  "list": "scanner_drop",
  "state": "installed",
  "reason": "repeated_hard_block",
  "evidence": {
    "score": 42,
    "hard_block_hits": 5,
    "distinct_categories": 2
  },
  "policy_version": 1,
  "created_at": 1783728000,
  "expires_at": 1783731600,
  "source": "automatic"
}
```

内核集合只用于快速匹配。原因、证据、操作者和状态历史保存在 VeryNginx 控制面，不依赖内核集合承载业务元数据。

---

## 6. 自动晋升策略

### 6.1 通用安全门槛

任何自动晋升都必须同时满足：

1. 功能开启且模式为 `enforce`。
2. IP 格式有效，地址族受支持。
3. IP 不属于现有 `ip_reputation.whitelist`、运行时自动白名单或可信基础设施。
4. IP 不是回环、链路本地、组播、未指定地址或本机管理地址。
5. 当前网络拓扑允许内核按该地址匹配真实数据包源。
6. 未超过目标集合容量。
7. 通过第 6.2 节定义的全局自动晋升令牌桶。
8. 候选证据仍在有效窗口内。

### 6.2 自动晋升速率限制

自动晋升使用一个跨 worker、跨 IPv4/IPv6、由 scanner 与 CC 共享的全局令牌桶。配置使用整数，避免不同实现对浮点补充速率产生差异：

```json
{
  "limit": 1000,
  "interval": 60,
  "burst": 1000
}
```

- `limit` 表示每 `interval` 秒补充的 token 数，`burst` 表示桶的最大 token 数。
- 一个 token 代表一次可能引起 nftables 写入的自动期望状态变更，包括首次自动晋升、`cc_drop` 升级为 `scanner_drop`，以及实际延长 `expires_at` 的自动续期。
- loose/strict observe 结果、安全门拒绝、未改变期望状态的重复证据、IPC 重试、已有期望状态的 reconciliation、到期和解除不消耗 token。
- manual 操作不使用自动晋升桶，但仍受管理 API 限流、白名单、TTL、集合容量和 Helper 协议限额约束。
- 令牌桶在地址、证据、白名单、拓扑、重叠和容量检查之后，在创建或延长期望状态之前执行。token 消耗与期望状态接受必须在策略调度器视角下原子完成。
- 无 token 时保持 `candidate`，记录固定结果 `rate_limited`，不创建可安装状态、不调用 Helper，也不进入无界重试队列；原证据仍有效时允许后续重新评估。
- observe 模式使用独立虚拟桶计算 `would_rate_limit`，不消耗 enforce 桶 token。
- 桶状态保存在 shared dict，记录当前 token 和最后补充时间。worker reload 不得把桶重置为满额；热加载降低 `burst` 时立即夹紧可用 token，但不撤销已安装条目。
- 桶状态损坏或不可用时，流量处理继续 fail-open，但新的自动内核晋升 fail-closed 并标记 degraded。
- Helper 对来自 Nginx peer 的所有 `add`/自动续期独立执行相同或更严格的硬变更限额，不能信任调用方提供的 `source` 来决定是否限速。Helper 的连接速率、IPC 请求速率和 batch 大小限制是独立协议防线，不能与本令牌桶混为一谈。

### 6.3 Scanner 晋升

Scanner 晋升适合使用多个高置信信号组合：

- 已进入 `ip_reputation.flagged`
- 在多个时间槽持续触发，而非单次突发
- 重复命中 hard block 规则
- 命中多个 URI 模式或多个攻击类别
- 命中 RCE、SQLi、路径遍历等高危类别
- 多次 Challenge 失败
- 非正常浏览器行为与攻击内容同时出现

不应单独触发晋升的信号：

- 单次 404
- 单次 WAF block
- 单次 Challenge
- 仅 User-Agent 异常
- 仅访问敏感路径但没有攻击内容
- 低置信推荐规则命中

初始 scanner 策略直接复用现有 IP 声誉阈值体系：

```text
条件 A：已 flagged
  - 总分 >= ip_reputation.threshold（当前默认 25）
  - 请求数 >= ip_reputation.min_requests（当前默认 3）
AND 条件 B：在 ip_reputation.window_size（当前默认 300 秒）内
             至少 3 次产生 waf_block 信号的 action=block 命中
THEN：晋升 scanner_drop
  - 初始 TTL = ip_reputation.flag_duration（当前默认 600 秒）
```

当前 `signals.waf_block` 默认权重为 5。在 UA diversity factor 未降低得分时，只有 `waf_block` 信号的 IP 通常第 `ceil(25 / 5) = 5` 次 block 命中达到 flagged 门槛；若 diversity factor 降低得分，则可能需要更多命中。此时“至少 3 次 block 命中”的独立证据门槛也已经满足。这里不是把 25 分和 `3 × 5 = 15` 分相加，而是同时要求：

1. 现有综合声誉评分已经达到 flagged 条件。
2. 证据中至少包含 3 次高置信 hard block。

这样，混合信号可以帮助 IP 达到 flagged，但仅由 404、Challenge 或低置信行为累计到 25 分时，不会直接晋升到内核 DROP。这里的 block 计数只统计实际产生 `waf_block` 信号的 `action="block"` 命中，不统计 hard-block 评估阶段中的 `accept` 或 `log` 规则。由于当前声誉槽只存加权总分，未来实现 Promotion Policy 时需要单独维护有界的 block 命中计数，不能从总分反推出命中次数。

block 命中证据复用现有 `lua_shared_dict ip_reputation`，不新增第二个计分系统。建议 key：

```text
ip_rep:kernel:waf_block:<ip>:<slot>
```

其中：

- `slot = floor(ngx.time() / ip_reputation.slot_size)`。
- 每次实际产生 `waf_block` 信号时使用 `shared:incr(key, 1, 0, window_size)` 原子递增。
- key TTL 使用运行时 `ip_reputation.window_size`，当前默认 300 秒。
- Promotion Policy 按现有 `slot_keys()` 语义汇总当前窗口内计数，并与 `scanner.min_hard_blocks` 比较。
- 计数 key 只存次数，不存加权分值；总分仍由现有 `ip_rep:waf:<ip>:<slot>` 维护。
- 如需枚举 observe 候选，维护有界候选索引，不能使用 `get_keys(0)` 扫描 shared dict。
- 索引达到容量时停止新增索引项并记录丢弃指标，不影响现有 WAF。
- 该短期证据可由请求重新生成，不写入 `kernel-blocking-state.json`。

首期不再把“跨 M 个时间槽”或“K 个 URI 模式”设为硬门槛。时间槽跨度、URI 模式数和攻击类别多样性先作为 observe 指标和审计证据，生产数据证明有必要后再决定是否加入条件。

首次封禁复用当前 600 秒 `flag_duration`。重复晋升可分级延长，但必须设置最大 TTL，避免自动形成永久黑名单。若管理员调整 `ip_reputation.threshold`、`signals.waf_block`、`window_size` 或 `flag_duration`，scanner 基础晋升行为应同步采用运行时配置，而不是在 `kernel_ip_blocking` 中复制这些数值。

### 6.4 CC 晋升

CC 的误封风险高于 scanner，尤其是 NAT、校园网、企业出口和移动网络。建议采用渐进流程：

```text
被引用频率规则首次超限
  -> 记录 CC violation evidence
  -> 执行该频率规则现有的应用层 block 响应
  -> 后台汇总连续多个 violation windows
  -> 可选关联同一证据期内由既有流程产生的 challenge_fail
  -> 临时 cc_drop
  -> TTL 到期自动解除
```

CC 不复制现有限频规则的 `limit`、`window`、matcher 或 key 维度，而是通过 `kernel_ip_blocking.cc.rule_ids` 显式引用 `config.rule.frequency_limit` 中已存在的规则。被引用规则必须：

- 存在且启用。
- 有稳定、唯一的 `rule.id`。
- `rule.key` 为 `"ip"`，或组合 key 中明确包含 `"ip"`。
- 使用自身的 `rule.limit`、`rule.window` 和 matcher 作为第一阶段超限定义。

当前 `frequency_limit` shared dict 仅保存原始请求计数，key 中没有 rule ID，也没有连续超限窗口、超限次数或候选索引；`/frequency/stats` 的有限 `get_keys()` 结果只适合展示，不能作为晋升数据源。因此实现 CC Promotion Policy 时，`frequency_limit` 插件必须在首次越过规则限额时额外产生有界证据：

```text
rule current 从 limit 变为 limit + 1
  -> 记录 { rule_id, ip, evidence_slot, exceeded_at }
  -> 每个原始计数 key 生命周期最多记录一次
```

#### Frequency Counter Key v2 与冷切换

现有限频原始计数 key 必须加入 rule ID，避免两条使用相同 `key` 维度的规则互相污染。v2 使用版本化命名空间：

```text
fl:v2:count:<encoded_rule_id>:<encoded_dimension_key>
```

超限窗口证据复用 `lua_shared_dict frequency_limit`，建议 key：

```text
fl:v2:kernel:violation:<encoded_rule_id>:<canonical_ip>:<evidence_slot>
```

其中：

- `limiter.build_key()` 的 v2 契约只返回规范化的维度部分，不再返回带 `fl:` 前缀的完整存储 key；调用方统一拼装上述命名空间。
- `rule_id` 和所有可变维度必须使用无分隔符碰撞的长度前缀编码、URL-safe 编码或固定摘要，不能直接用冒号拼接原始值。IPv4/IPv6 必须先规范化。
- 保留现有限频“计数 key 首次创建后按 `rule.window` TTL 过期”的窗口语义，不改成对齐时间槽。
- 晋升证据单独使用 `evidence_slot = floor(ngx.time() / rule.window)`，它只用于把超限事件归入稳定、可汇总的观察槽，不改变原始限频行为。
- 当 `current == rule.limit + 1` 时用 `shared:add()` 写入当前 slot marker；后续同一原始计数生命周期中 `current` 更大，不会重复记录。
- 若两个固定 TTL 计数生命周期在边界情况下落入同一 evidence slot，`shared:add()` 会保守合并为一次证据，不会重复放大晋升计数。
- TTL 至少为 `rule.window × (cc.min_violation_windows + 1)`，确保最早证据在评估窗口内仍可读取。
- Promotion Policy 只统计仍未过期的证据 marker。
- 维护有界的 CC 候选索引，不能依赖 `/frequency/stats` 或 `get_keys()` 枚举。
- 计数 key 和证据 key 都不写持久化快照；流量恢复后可重新生成。

首次部署 v2 采用明确的冷切换契约：

1. 所有 frequency rules 同时切换到 v2 key，不只切换 `cc.rule_ids` 引用的规则。
2. 不对旧 `fl:*` key 双读、双写或转换；旧 key 不枚举、不删除，按原 TTL 自然过期。
3. 所有活动限频窗口在切换时重新开始，客户端可能在最长一个 `rule.window` 内获得一次新额度。升级状态和发布说明必须明确显示该行为。
4. CC violation evidence 从空历史开始，旧计数不能解释为连续超限窗口。共享状态记录 `counter_namespace="v2"` 和统一 `cutover_epoch`。
5. 只有全部证据都晚于 `cutover_epoch` 且已满足 `min_violation_windows` 时才允许 CC 自动晋升；在此之前状态为 `warming_up`。
6. graceful reload 期间不得让旧、新 worker 长期同时执行不同 key 语义。部署流程必须完成 OpenResty 冷重启；首期不实现 dual-read/dual-write。
7. 回滚到旧代码会再次重置窗口，不做反向状态转换。
8. 所有启用的 frequency rule 在激活前必须有非空、唯一、稳定的 `rule.id`。修改 ID 被视为有意创建新计数命名空间并重置该规则的计数与证据。
9. `/frequency/stats` 只枚举规范的 v2 counter 命名空间，不能把旧 key 或 violation marker 混入原始限频统计。

初始策略示意：

```text
条件 A：至少一个被引用的 IP 限频规则发生超限
AND 条件 B：达到 min_violation_windows 个超限证据窗口
AND 条件 C：若 require_challenge_fail=true，则同一规范化 IP 在 CC 证据期内
              存在由既有 WAF/Challenge 流程产生的 challenge_fail
THEN：晋升 cc_drop
```

建议的附加判断包括：

- 连续或近期多个证据窗口超过 frequency limit
- 达到最小观测时长
- 同一证据期内已有 Challenge 失败或无正常会话行为
- 请求速率显著高于正常峰值
- 不在白名单、可信代理和健康检查列表

不建议只依据瞬时 QPS 自动进入内核集合。正常流量突发应优先由 Nginx 限流吸收。

`min_violation_windows=3` 和 `require_challenge_fail=true` 是新的晋升策略参数，不是现有 frequency rule 默认值。它们必须在 observe 阶段同时评估宽松和严格结果后校准；首期 enforce 不应在没有候选数据时把示例值视为经过验证的安全默认值。`rule_ids` 为空时不产生任何 CC 候选。

`require_challenge_fail=true` 不表示 frequency 插件调用 `browser_verify`，也不改变插件优先级。若该 IP 在证据期内没有独立产生的有效 `challenge_fail`，strict CC 条件不成立。

### 6.5 手动封禁

人工操作必须要求：

- 已认证管理员
- CSRF 验证
- 审计日志
- 明确集合、原因和 TTL
- 永久封禁需二次确认
- 禁止封禁本机、管理出口和受保护地址
- 静态或自动白名单覆盖所有人工 DROP；普通 manual 操作不能强制绕过白名单

### 6.6 续期与降级

- 同一 IP 重复晋升时不无限叠加 TTL。
- 每次续期记录原因和策略版本。
- 达到最大封禁时长后仍持续攻击，可提升到更长等级，但不能自动转永久。
- Helper 故障时保留 Lua 层 flagged/limit 行为，不将同步失败视为已安装。
- `ip_reputation.whitelist` 或自动白名单新增后应尽快撤销对应自动封禁并刷新执行面的 `allow` 快照。

#### 白名单 Generation、Lua 缓存与执行面刷新

白名单变更属于高优先级安全事件，不能等待默认 30 秒 reconciliation。静态白名单和运行时自动白名单共享一个复合 generation：

```text
ip_rep:whitelist_epoch
ip_rep:whitelist_sequence
ip_rep:wl_cache:<epoch>:<sequence>:<canonical_ip>
```

generation 语义如下：

1. `epoch` 是每次 Nginx master 启动生成的不可预测 boot ID，`sequence` 是该 epoch 内从 1 开始原子递增的整数；比较规则为 epoch 必须相等，同一 epoch 内 sequence 只能增加，不能依赖跨重启整数单调性。
2. `is_whitelisted()` 每次查缓存前读取当前 `{epoch, sequence}`，正、负缓存都只写入 generation-qualified key。引入本功能后不得再读写无 generation 的 `ip_rep:wl_cache:<ip>`。
3. 静态白名单变更顺序固定为：验证并规范化完整候选白名单；`config.save()` 原子持久化并激活；成功后原子递增 sequence；将携带新 `{epoch, sequence}` 和规范化摘要的完整 allow snapshot 放入高优先级队列。保存失败不得递增 sequence 或修改 Helper。
4. sequence 递增同时失效所有受精确 IP 或 CIDR 变化影响的正、负缓存。旧 generation 缓存只依赖短 TTL 自然回收，不调用 `get_keys()` 扫描，也不逐 IP 删除。
5. `/config`、import、rollback、热加载和专用 reputation API 都必须经过同一白名单发布路径，不能只在 `add_whitelist()`/`remove_whitelist()` 中局部失效。
6. 运行时自动白名单创建、显式删除和过期都递增同一个 sequence。自动白名单正缓存 TTL 还必须限制为不超过该 auto-allow 的剩余 TTL，避免正缓存越过实际到期时间。
7. 发送给 Helper 的是完整规范化静态白名单加当前未过期 auto-allow，不是本次变更的 delta。当前请求 worker 可用一次性 `ngx.timer.at(0, ...)` 异步尝试刷新，但不能阻塞 API，也不能假设 timer 位于 worker 0。
8. `ensure_base` 建立当前受信任 epoch；在其成功前，任何 `replace_allow_snapshot` 都不得发往 Helper，只保留“需要刷新最新 snapshot”的有界合并标记。bootstrap 成功后由 worker 0 立即发送最新 generation，不能依次重放过期 snapshot。
9. Helper 此后只接受当前 epoch。相同 epoch 内仅接受更大的 sequence；相同 `{epoch, sequence}` 且摘要相同视为幂等，摘要不同返回 `generation_conflict`，较小 sequence 或非当前 epoch 返回 `stale_generation`。
10. Helper 在一个 nftables transaction 中替换 `allow`，并移除被覆盖的 `scanner_drop`、`cc_drop` 和 `manual_drop` 条目；transaction 成功后才更新已安装 generation。
11. 控制面 `{epoch, sequence}` 与 Helper 已安装值不一致时状态为 `allow_refresh_pending`。在途旧刷新不得覆盖更新 generation；worker 0 reconciliation 始终重发最新完整 snapshot。
12. 相关期望状态记录 `whitelist_override`；人工条目进入 `suppressed_by_allow`，自动条目清除。白名单删除后不自动恢复被抑制的人工条目。
13. Nginx 重启生成新 epoch 后，先由 `ensure_base` 建立新 epoch，再发送 sequence 1 的完整 snapshot；Helper 不得把上次 boot 的 snapshot 误认为当前状态。

API/Dashboard 应显示 `allow_refresh_pending`、`installed` 或 `degraded`，不能在异步刷新完成前声称内核已经放行。紧急操作可显式触发一次立即刷新，但仍必须经过固定 Helper 操作，不能执行任意防火墙命令。

---

## 7. 客户端 IP 与网络拓扑

### 7.1 核心约束

内核防火墙只能匹配数据包的网络源地址，不能直接匹配 HTTP Header 中的逻辑客户端 IP。

只有满足以下条件时，本机内核封禁才有效：

```text
VeryNginx 判定的客户端 IP == 到达本机数据包的可匹配源 IP
```

### 7.2 直连源站

客户端直接连接 VeryNginx 时，本机可以按源 IP 封禁，是本方案的主要适用场景。

### 7.3 CDN、反向代理和负载均衡

如果前面存在 CDN、L4/L7 负载均衡或反向代理：

- 内核看到的通常是代理节点 IP。
- `X-Forwarded-For` 中的真实客户端 IP 无法被本机 nftables 直接匹配。
- 把 Header 中的地址加入本机集合不会拦住真实客户端。
- 错误地加入代理节点 IP 可能导致全部正常流量中断。
- 未经可信 realip 配置处理的 Header 可以被攻击者伪造。

因此：

- CDN/代理场景默认禁止自动内核晋升。
- 不能仅因为 Nginx `remote_addr` 被 realip 模块改写，就假设内核也能匹配该地址。
- 若需要边缘封禁，应对接 CDN/负载均衡防火墙 API，或在真实源 IP 可见的边缘节点部署执行面。该能力不属于本草案首期范围。

### 7.4 拓扑安全门

建议配置显式模式：

| 模式 | 行为 |
|------|------|
| `direct` | 允许自动晋升，管理员确认源站直连 |
| `proxied` | 禁止自动本机封禁，仅 observe |
| `unknown` | 仅检测明显风险并告警，不自动假定安全 |

不能仅靠应用层自动推断网络拓扑后直接启用 enforce。

---

## 8. 权限分离与 Helper

### 8.1 禁止 worker 直接执行系统命令

不采用以下实现：

```lua
io.popen("nft add element ...")
```

原因：

- 创建进程会阻塞或拖慢 worker。
- 大规模 CC 下可能形成 shell 风暴。
- Nginx 用户通常没有 `CAP_NET_ADMIN`。
- 字符串拼接存在命令注入风险。
- 无法可靠处理超时、并发、幂等和部分失败。

### 8.2 Helper 权限

Helper 可采用以下部署之一：

- 宿主机 systemd 服务，授予最小 capability。
- root 启动后降权，仅保留必要能力。
- 专用 sidecar，授予 `NET_ADMIN`，但不授予主 Nginx 容器。

不建议：

- 给 VeryNginx/OpenResty 容器 `--privileged`
- 给 Nginx worker root 权限
- 允许 Helper 执行客户端传入的任意命令

### 8.3 IPC Protocol v1

Protocol v1 使用本地 Unix Domain Socket：

```text
/run/verynginx/firewall-helper.sock
```

协议采用严格 request/response 模型，每个通过 framing 并可解析出 envelope 的请求必须得到一个且仅一个响应。无法提取 `request_id` 的 framing/parser 错误使用 `request_id=null` 的协议级错误响应后关闭连接。控制面可以在内部排队，但不得向 Helper 发送无确认的单向 mutating event。

#### 8.3.1 Transport、framing 与连接管理

- 每个 frame 为 4 字节无符号大端长度，后接恰好一个 UTF-8 JSON object。
- frame 最大 1 MiB；长度为 0、超限、截断、包含多个 JSON 值、尾随非空数据或无效 UTF-8 时返回协议错误并关闭连接。
- Helper 在读取 payload 前校验 frame 长度和 Unix peer credentials。
- 客户端使用持久顺序连接，每条连接同一时间最多一个 in-flight 请求，不支持 pipelining。连接最多处理 100 个请求或存活 30 秒，达到任一条件后正常重连。
- connect timeout 为 100 ms，read/write timeout 为 2 秒，idle timeout 为 5 秒。EOF、timeout 或 Helper 重启后使用带抖动的指数退避重连，初始 100 ms、上限 5 秒。
- Helper 最多接受 16 个并发客户端连接；超限返回 `rate_limited` 或立即拒绝。控制面 dispatch 队列必须有界，断线期间不得无限累积。
- 请求 worker 不直接持有阻塞式 IPC 会话。周期批处理由 worker 0 timer 上下文发送；高优先级 allow 刷新由一次性异步 timer 发送。

#### 8.3.2 通用请求与响应 Envelope

所有请求使用以下 envelope：

```json
{
  "version": 1,
  "request_id": "01J...",
  "operation": "add",
  "source": "automatic",
  "payload": {}
}
```

要求：

- `version` 必须是整数 `1`。
- `request_id` 必须是 1 至 64 字节的 URL-safe 标识符。
- `operation` 和 `source` 必须来自固定枚举；`source` 只允许 `automatic|manual|reconcile|whitelist`。`source` 只用于语义、审计和控制面策略，不能作为 Helper 授权或绕过硬限额的依据。
- `payload` 必须符合对应操作 schema。未知顶层字段和未知安全敏感 payload 字段一律拒绝。
- 字符串、数组深度和数组项数受限；IP、CIDR、地址族、时间戳和 generation 在进入 Executor 前完成规范化与范围验证。

成功响应：

```json
{
  "version": 1,
  "request_id": "01J...",
  "ok": true,
  "result": {},
  "error": null
}
```

失败响应：

```json
{
  "version": 1,
  "request_id": "01J...",
  "ok": false,
  "result": null,
  "error": {
    "code": "stale_generation",
    "message": "bounded non-sensitive text",
    "retryable": true,
    "details": {}
  }
}
```

`message` 和 `details` 不得包含原始 nft 命令、完整 nft stdout/stderr、白名单快照或敏感配置。稳定错误码至少包括：

```text
invalid_frame
unsupported_version
invalid_schema
unsupported_operation
unauthorized_peer
invalid_scope
invalid_address
protected_address
whitelisted
stale_generation
generation_conflict
idempotency_conflict
capacity_exceeded
rate_limited
unavailable
timeout
nft_failed
internal_error
```

每个错误码固定标注是否可重试。schema、授权、保护地址、白名单、generation conflict 和 idempotency conflict 不可盲目重试；timeout、unavailable 和部分 `nft_failed` 可使用同一 `request_id` 有界重试。

#### 8.3.3 操作与 Batch 语义

Protocol v1 只允许以下操作：

| 操作 | 类型 | 核心 payload/result 契约 |
|------|------|--------------------------|
| `probe` | 只读 | 返回 `protocol_min/max`、capabilities、Helper 版本和受支持 nftables 特性 |
| `health` | 只读 | 返回 Helper、Executor、table generation、allow `{epoch,sequence,digest}` 和 degraded 原因 |
| `ensure_base` | 变更 | 接收完整受保护地址、端口、期望 table generation 和当前 whitelist epoch；作用域为空时拒绝 enforce |
| `add` | 变更、批量 | `items[]` 包含逻辑集合、规范化地址、地址族、绝对 `expires_at` 或仅限 manual 的 permanent 标记、策略版本和原因枚举 |
| `delete` | 变更、批量 | `items[]` 包含逻辑集合、地址和地址族；删除不存在条目视为成功 |
| `list` | 只读 | 仅列出自有对象，使用 opaque cursor，单页最多 1000 项 |
| `replace_allow_snapshot` | 变更 | 接收完整静态 CIDR/IP 与未过期 auto-allow、`{epoch,sequence}` 和 canonical digest |
| `reconcile` | 变更、分块 | 接收 generation-checked 期望状态分块，返回新增、更新、删除、跳过和失败数量 |
| `flush_owned` | 变更 | scope 只允许 `auto|all|detach`，不能接收任意 table/chain/set 名 |

通用 batch 规则：

- 单个 mutating 请求最多 1000 项，且仍受 1 MiB frame 上限约束。
- 同一请求中的重复项先按规范化 identity 合并；不能因顺序不同产生不同结果。
- 一个请求映射为一个 nftables transaction，首期采用 all-or-nothing。事务失败时 `ok=false`，不得报告部分条目已安装。
- `add` 的过期自动条目直接返回固定 skipped 结果，不重新赋予完整 TTL；重复 add 不得缩短现有到期时间。
- `replace_allow_snapshot` 必须在同一 transaction 中更新 allow 并移除被覆盖的所有自有 DROP 条目。
- `reconcile` 超过单批上限时由控制面分块。每块携带同一 `snapshot_id`、固定 desired-state generation、从 0 连续递增的 `chunk_index` 和 `final_chunk`；每块内部原子。
- Helper 可以逐块幂等补装/更新条目，但在收到并成功处理该 snapshot 的 `final_chunk=true` 前不得依据“未出现”删除任何现有条目。最终块成功后才按完整 snapshot 身份索引执行权威删除并提交该 desired-state generation。
- chunk 缺失、乱序、generation 改变或 snapshot 超时会中止该 snapshot，丢弃 Helper 的暂存索引且不执行权威删除；已完成的幂等补装由下一轮 reconciliation 重新确认。
- `list` cursor 仅在同一 table generation 内有效；generation 变化后返回 `stale_generation`，调用方重新分页。

#### 8.3.4 幂等、排序与版本协商

- Helper 为 mutating `request_id` 保存有界幂等缓存，默认 TTL 10 分钟、最多 10000 项。
- 相同 ID 加相同规范化请求摘要返回首次结果，不重复执行；相同 ID 加不同摘要返回 `idempotency_conflict`。
- timeout 后重试必须复用原 `request_id`，不能生成新 ID。
- whitelist `{epoch,sequence}`、desired-state generation 和 nftables table generation 独立携带和比较，旧 generation 不得覆盖新状态。
- `probe` 返回 `protocol_min`、`protocol_max` 和 capability flags。major version 不兼容时所有 mutating 请求返回 `unsupported_version`。
- v1 可增加调用方明确声明支持的只读 result 字段；未知请求字段默认拒绝，不能静默忽略安全控制。

#### 8.3.5 身份认证与资源限制

- Socket 父目录由 root 拥有且不可被 nginx 用户替换，Socket owner/group/mode 固定为 `root:verynginx 0660`。
- Helper 使用 `SO_PEERCRED` 或目标平台等价机制验证固定 UID/GID allowlist，文件权限不是唯一认证手段。
- 启动时安全处理 stale socket；路径类型、owner 或 mode 异常时拒绝启动并告警。
- Helper 独立执行连接数、frame、batch、TTL、容量、请求速率和 DROP add/renew 硬限额。来自 Nginx peer 的 `source` 声明不改变授权或限额；delete、allow refresh 和紧急解除不能被 DROP add 限额阻塞。
- 调用方不能提供 table、chain、set、命令、可执行文件路径或任意 nftables 文本。
- `replace_allow_snapshot` 是唯一可更新 Helper 白名单视图的操作；单个 `add` 请求不能携带或覆盖白名单。

---

## 9. nftables 执行层

### 9.1 支持范围

本功能只支持 nftables，不实现 ipset/iptables 后端，也不提供运行时 backend 选择或 fallback。

成立前提：

- VeryNginx 与配套 LNMP 脚本作为受控部署整体发布。
- LNMP 脚本只支持其明确声明的最近两个 Debian/Ubuntu 版本。
- 安装脚本负责安装 nftables、检查内核能力并部署 Helper。
- 超出支持矩阵的发行版可以继续运行现有 Lua WAF，但内核封禁标记为 unavailable。

`iptables-nft` 兼容前端、UFW 和 Docker 可能仍通过 netfilter/nftables 管理规则，属于共存测试对象，不是 VeryNginx 的备用后端。

### 9.2 内部 Executor 接口

虽然只有一个执行实现，仍保留固定内部接口：

```text
probe()                         -> capabilities
ensure_base(config)            -> ok/error
add(list, ip, family, ttl)      -> ok/error
delete(list, ip, family)        -> ok/error
contains(list, ip, family)      -> bool/error
list(list, family, cursor)      -> entries/error
reconcile(desired_snapshot)     -> result
flush_owned(scope)              -> result
health()                        -> status
```

IPC 操作名与 Nft Executor 方法是两层独立契约，不要求一一映射；Helper 可以把一个 Protocol v1 batch 编译为一次或多次内部方法调用，但对外仍遵守请求级原子性。该接口用于：

- 隔离 Promotion Policy 与 nftables 命令格式。
- 对策略层进行 mock 和单元测试。
- 集中处理参数校验、批量 transaction、超时和错误映射。
- 将来更换 nftables 调用方式时不影响业务层。

它不是 backend registry，不实现 adapter factory，也不接受用户选择实现。业务策略不得出现 `nft` 命令文本。

### 9.3 自有 table、chain 和 set

使用独立的 VeryNginx table、chain 和带 timeout 的 set。概念结构：

```text
table inet verynginx
  set allow_v4          type ipv4_addr, flags interval
  set allow_v6          type ipv6_addr, flags interval
  set scanner_drop_v4   type ipv4_addr, flags timeout
  set scanner_drop_v6   type ipv6_addr, flags timeout
  set cc_drop_v4        type ipv4_addr, flags timeout
  set cc_drop_v6        type ipv6_addr, flags timeout
  set manual_drop_v4    type ipv4_addr, flags timeout
  set manual_drop_v6    type ipv6_addr, flags timeout
  chain prerouting      hook prerouting, priority raw
```

要求：

- 使用原子 transaction 更新批次。
- 对自动集合使用 nftables 元素 timeout。
- manual set 也启用 timeout，以支持明确 TTL；永久人工条目不设置 element timeout。
- `allow` 集合使用 interval 语义，直接保存规范化的精确 IP 和 CIDR，不展开网段。
- `allow` 集合由现有 `ip_reputation.whitelist` 和运行时自动白名单派生。
- IPv4 与 IPv6 使用独立 set，但统一放在 `table inet verynginx`。
- 只管理 `table inet verynginx`，不修改用户已有 table。
- 初始化前检查同名 table 是否带有本系统可识别的结构和 generation，不能接管来源不明的同名对象。
- 清理时只删除 VeryNginx 自有 table。

### 9.4 规则位置与作用域

优先考虑在 conntrack 和 Nginx 之前丢弃，但实际 hook/priority 必须在支持的 Debian/Ubuntu 版本上验证。

规则至少匹配：

- 目标地址属于本机 `protected_addresses`
- 协议为 TCP
- 目标端口属于 `protected_ports`
- 流量目标为本机，不匹配转发流量

不能只按源 IP 在整个 `PREROUTING` 上无条件 DROP，否则可能同时阻断该 IP 对 SSH、数据库或同机其他服务的访问。是否提供 `host_wide` 模式属于后续独立决策。

仍需验证与以下组件共存：

- UFW
- `iptables-nft` 兼容前端
- Docker 自动生成的规则
- 用户已有 nftables table
- 云主机安全代理

firewalld 和 Kubernetes/CNI 不属于配套 LNMP 的首期支持矩阵，但测试和文档应明确为 unsupported，而不是静默假定兼容。任何情况下都不能假设 VeryNginx 是系统唯一 netfilter 管理者。

### 9.5 Helper 调用 nftables

首期允许 Helper 使用固定绝对路径批量调用：

```text
/usr/sbin/nft -f -
```

约束：

- 不经过 `sh -c`，不执行拼接后的 shell 命令。
- table、chain、set 名称固定。
- IP、CIDR、端口、TTL 必须先由严格解析器验证和规范化。
- 一批变更生成一个 nftables transaction，通过标准输入提交。
- 使用 `nft -j list ...` 或等价结构化接口读取状态，不解析面向人的终端文本。
- 限制每批条目数、输入字节数、执行超时和输出大小。
- 子进程失败必须映射为结构化错误，并由 reconciliation 重试。

未来如果进程开销成为瓶颈，可以在同一个 Executor 接口后改用 libnftables 或直接 Netlink。这属于 nftables 调用实现优化，不是新增防火墙后端。

### 9.6 安装与能力检查

配套 LNMP 脚本负责：

1. 安装 nftables 用户态工具。
2. 检查 `/usr/sbin/nft` 和所需内核能力。
3. 验证 `inet` family、interval set、timeout element 和原子 transaction。
4. 安装并启用 Helper systemd service。
5. 创建 Unix Socket 目录、用户组和权限。
6. 执行只读 capability probe。
7. 报告 UFW、Docker 或已有同名 table 等潜在冲突。

能力检查成功只表示功能可用，不自动进入 enforce。初次安装仍保持 disabled/observe，需要管理员确认拓扑、目标地址和端口。

如果 nftables 不可用或 capability probe 失败：

- VeryNginx 和 Lua WAF 正常运行。
- 内核封禁状态为 unavailable/degraded。
- 不创建部分 table/chain/set。
- 不回退到 ipset/iptables。

---

## 10. 一致性、持久化与恢复

### 10.1 期望状态与实际状态

- **期望状态**：VeryNginx 判断应该处于封禁状态的条目。
- **实际状态**：当前内核集合中的条目。

API 和 Dashboard 必须区分：

```text
candidate
promoted
dispatch_pending
installed
expired
drifted
helper unavailable
```

`dispatch_pending` 同时覆盖 queued、重试等待和 sent/in-flight，并通过子状态区分。Protocol v1 mutating 响应只在请求级 nftables transaction 成功或失败后返回，因此不存在独立的 `helper_accepted` 状态。只有成功响应后才能显示 `installed`，IPC 写入成功或进入队列都不能提前视为安装完成。

### 10.2 批处理

- 同 IP、同集合的短时间重复事件合并。
- 批量发送给 Helper。
- 自动集合以 `expires_at` 为准，Helper 转换为剩余 TTL。
- 过期事件不再安装。
- 队列必须有容量上限，溢出时记录指标并继续由 Lua WAF 防护。

### 10.3 `core.init` 生命周期与 Scheduler Wiring

`kernel_blocking` 只暴露可调用函数，不自行注册周期 timer。`core.init` 是周期任务和退出回调的唯一所有者；第 6.6 节白名单高优先级刷新使用当前 worker 一次性 `ngx.timer.at(0, ...)` 是明确例外。

```text
core.init.init()
  1. config.load_from_file()
  2. 初始化 shared state
  3. ip_reputation.restore()
  4. kernel_blocking.restore()
  5. 继续 matcher/plugin 初始化

core.init.init_worker(), worker 0
  1. 启动后一次性 kernel_blocking.reconcile(now)
  2. 自重调度 batch callback:
       kernel_blocking.process_candidates(now)
       kernel_blocking.flush_dispatch_queue(now)
  3. 自重调度 reconcile callback:
       kernel_blocking.reconcile(now)
  4. 每 600 秒统一 persistence callback:
       ip_reputation.persist()
       kernel_blocking.persist()
  5. worker 退出轮询:
       ip_reputation.persist()
       kernel_blocking.persist()
```

调度契约：

- batch callback 按顺序先评估候选、后派发，使用当前运行时 `batch_interval`。
- reconcile callback 使用当前运行时 `reconcile_interval`。
- interval 可热加载的 callback 使用自重调度 `ngx.timer.at()`，每次开始时读取当前已规范化配置，不能因配置变更累积多个 `timer.every()` 链。
- callback 必须处理 `premature` 和 `ngx.worker.exiting()`；每个模块调用分别 `pcall`，一个模块失败不能阻止其他模块持久化或下一次正常重调度。
- reconciliation、persistence 和 dispatch 各自使用 token 化、带 TTL 的 shared-dict lease 或等价 single-flight guard，防止慢调用重叠以及 graceful reload 时两个 worker generation 同时执行。worker 异常退出后 lease 必须自动过期。
- `persist()` 内仍保留 worker 0 防御性检查。退出轮询检测到 exiting 后每个模块只调用一次，不再重调度。
- 启动恢复只重建期望状态，不执行 Socket I/O，不假定内核条目仍存在；首次 reconciliation 只能在 `init_worker` 后运行。
- disabled/observe 模式可以执行 probe、health 和只读 drift 检查，但不得派发 add/delete 等 mutating 自动操作。

现有 IP 声誉状态继续写入：

```text
configs/ip-reputation-flagged.json
```

内核封禁期望状态使用独立文件：

```text
configs/kernel-blocking-state.json
```

不把两类状态合并进同一 JSON，原因是它们的 schema、版本、生命周期和失败恢复语义不同。

快照要求：

- 使用版本化 payload。
- 保存 promoted/installed 期望状态、人工封禁及绝对 `expires_at`，不保存可重建的短期请求队列。
- 使用同目录临时文件加原子 rename。
- `persist()` 内仍保留 worker 0 防御性检查，与现有 `ip_reputation.persist()` 一致。
- 启动恢复时丢弃已经过期的自动条目，并按 `expires_at - now` 计算剩余 TTL，不能重新赋予完整 TTL。
- 人工永久封禁和未过期人工 TTL 封禁必须恢复。
- 快照缺失、损坏或版本不支持时 fail-open，记录告警但不阻断 Nginx 启动。
- 恢复只建立期望状态，不直接假定内核已安装；进入 `init_worker` 后由 worker 0 触发 Helper reconciliation。

候选和短期批处理队列保留在 shared dict 的有界索引中，不在每次请求中同步写文件，也不依赖 worker-local Lua table。若生产规模证明独立 JSON 快照不足，再评估 SQLite 或 Helper 自有存储。

### 10.4 Reconciliation

`core.init` worker 0 注册并独占 reconciliation 调度，`kernel_blocking` 仅实现可调用回调：

1. 读取 Helper health 和 nftables table generation。
2. 分页读取自有集合实际状态。
3. 与未过期的期望状态比较。
4. 批量补装缺失条目。
5. 删除不再期望且由自动策略创建的条目。
6. 保留无法确认所有权的外部条目并告警。
7. 记录耗时、差异数量和失败原因。

---

## 11. 配置草案

以下是 Protocol/Policy v1 的规范默认值，不只是字段形状。默认配置只能安全地运行 disabled/observe；CC 的示例阈值仍需通过 observe 校准，未显式确认前不能进入 enforce：

```json
{
  "kernel_ip_blocking": {
    "enabled": false,
    "mode": "observe",
    "topology": "unknown",
    "fail_policy": "open",
    "helper_socket": "/run/verynginx/firewall-helper.sock",
    "scope": "web",
    "protected_addresses": [],
    "protected_ports": [],
    "batch_interval": 1,
    "reconcile_interval": 30,
    "max_entries": {
      "scanner": 100000,
      "cc": 50000,
      "manual": 10000
    },
    "scanner": {
      "enabled": true,
      "require_flagged": true,
      "min_hard_blocks": 3,
      "max_ttl": 86400
    },
    "cc": {
      "enabled": true,
      "enforce_ready": false,
      "rule_ids": [],
      "ttl": 300,
      "max_ttl": 1800,
      "min_violation_windows": 3,
      "require_challenge_fail": true
    },
    "ipv4": {
      "enabled": true
    },
    "ipv6": {
      "enabled": false,
      "prefix_aggregation": false
    },
    "promotion_rate_limit": {
      "limit": 1000,
      "interval": 60,
      "burst": 1000
    }
  }
}
```

### 11.1 递归 Schema 与默认值归一化

`kernel_ip_blocking` 必须作为递归 schema node 正式加入 `core/config.lua`，不能只定义一个带完整默认 table 的顶层字段。实现必须满足：

1. 每个 object 明确定义子字段；缺失叶子字段逐层 deep-copy 默认值。
2. 部分对象必须安全补全。例如只提供 `cc.rule_ids` 时，仍要补全 `cc.ttl`、`cc.max_ttl`、`cc.require_challenge_fail` 和其他同级字段。
3. 递归合并过程中先验证用户显式提供值的形状和类型，错误值不能被默认值静默替换。
4. 跨字段验证针对递归规范化后的完整候选配置执行，验证成功后才允许原子持久化和激活。
5. object、dense array、boolean、string 和 integer 必须严格区分；Lua table 不能在没有形状检查时同时当作 map 和 array。
6. `kernel_ip_blocking` 下未知字段一律拒绝，避免安全控制拼写错误被 `deep_copy` 保留但运行时忽略。
7. `enabled=false` 只关闭运行行为，不豁免对用户显式提供字段的 schema 验证。
8. 任一嵌套字段或引用无效时整次 save/load activation 失败，不允许部分应用。
9. 规范化后的运行时快照保持不可变；模块不得直接修改活动配置中的嵌套 table。

加载和保存顺序必须调整为：

```text
parse raw candidate
  -> recursive type/shape check and default merge
  -> effective cross-field/reference validation
  -> persist
  -> atomically activate immutable snapshot
```

现有只补顶层默认值的 `normalize_defaults()` 不能直接承担本 section 的安全语义。

### 11.2 字段定义

| 字段 | 类型 | 默认值 | v1 约束 |
|------|------|--------|---------|
| `enabled` | boolean | `false` | `false` 表示 disabled；`mode` 不增加第三个 disabled 枚举 |
| `mode` | enum | `observe` | 只允许 `observe|enforce` |
| `topology` | enum | `unknown` | 只允许 `unknown|direct|proxied`；只有显式 `direct` 可 enforce |
| `fail_policy` | enum | `open` | v1 只允许 `open` |
| `helper_socket` | string | `/run/verynginx/firewall-helper.sock` | v1 必须等于该绝对路径，不允许 NUL、`..` 或替代目录 |
| `scope` | enum | `web` | v1 只允许 `web` |
| `protected_addresses` | dense string array | `[]` | 唯一、规范化的本机单播精确 IPv4/IPv6；不接受 CIDR |
| `protected_ports` | dense integer array | `[]` | 唯一整数，范围 `1..65535` |
| `batch_interval` | integer seconds | `1` | `1..60` |
| `reconcile_interval` | integer seconds | `30` | `5..3600` 且不小于 `batch_interval` |
| `max_entries.scanner` | integer | `100000` | `1..1000000`，同时受 Helper 硬上限约束 |
| `max_entries.cc` | integer | `50000` | `1..1000000`，同时受 Helper 硬上限约束 |
| `max_entries.manual` | integer | `10000` | `1..1000000`，同时受 Helper 硬上限约束 |
| `scanner.enabled` | boolean | `true` | 关闭后不生成 scanner 候选 |
| `scanner.require_flagged` | boolean | `true` | v1 enforce 必须为 `true` |
| `scanner.min_hard_blocks` | integer | `3` | `1..100` |
| `scanner.max_ttl` | integer seconds | `86400` | `60..604800`，且不小于运行时 `ip_reputation.flag_duration` |
| `cc.enabled` | boolean | `true` | 空 `rule_ids` 时不生成 CC 候选 |
| `cc.enforce_ready` | boolean | `false` | 只有 observe 校准并由管理员显式改为 `true` 后，CC 才可在全局 enforce 模式安装 |
| `cc.rule_ids` | dense string array | `[]` | 唯一、非空 ID；引用完整性见 11.4 |
| `cc.ttl` | integer seconds | `300` | `60..3600` |
| `cc.max_ttl` | integer seconds | `1800` | `cc.ttl..604800` |
| `cc.min_violation_windows` | integer | `3` | `1..100` |
| `cc.require_challenge_fail` | boolean | `true` | 语义见 6.4，不会触发新的 Challenge |
| `ipv4.enabled` | boolean | `true` | enforce 时至少一个地址族启用 |
| `ipv6.enabled` | boolean | `false` | 仅允许精确 IPv6 地址 |
| `ipv6.prefix_aggregation` | boolean | `false` | v1 只允许 `false` |
| `promotion_rate_limit.limit` | integer | `1000` | `1..100000`，每 interval 补充 token 数 |
| `promotion_rate_limit.interval` | integer seconds | `60` | `1..3600` |
| `promotion_rate_limit.burst` | integer | `1000` | `1..100000`，令牌桶最大余额 |

容量、TTL 和速率上限是 v1 的协议级硬边界，observe 数据只能在边界内调整配置；修改硬边界需要提升 policy/protocol version 并重新评审。

### 11.3 跨字段安全验证

- `enabled=true` 且 `mode=enforce` 时必须同时满足：`topology=direct`、`fail_policy=open`、`scope=web`、`protected_addresses` 非空、`protected_ports` 非空，并至少启用一个与保护地址一致的地址族。
- 保存配置时验证地址语法、规范化、重复项和地址族；激活 enforce 或 Helper `ensure_base()` 时还必须独立验证每个 protected address 当前确属本机单播地址。
- 首期不自动推断接口地址，也不把空数组解释为所有本机地址。空保护作用域只允许 disabled/observe。
- `scanner.require_flagged=false`、`ipv6.prefix_aggregation=true` 或 `cc.enabled=true && cc.enforce_ready=false` 不得产生对应类型的 enforce 安装；最后一种组合仍允许 CC observe。
- 不新增 `never_block_addresses` 或其他并行来源白名单；静态来源白名单统一复用 `ip_reputation.whitelist`，运行时自动白名单作为附加临时 allow 状态。
- Helper 和内核 `allow` 使用同一 generation 的完整规范化快照，不能从 kernel section 接受另一份白名单。
- Scanner 的总分阈值、最少请求数、证据窗口、`waf_block` 权重和初始 TTL 分别读取 `ip_reputation.threshold`、`min_requests`、`window_size`、`signals.waf_block` 和 `flag_duration`，不得在本 section 重复配置。
- `scanner.min_hard_blocks` 只统计产生 `waf_block` 信号的 `action="block"` 命中，是独立证据门槛，不是附加分数。
- `cc.max_ttl >= cc.ttl`，`scanner.max_ttl >= ip_reputation.flag_duration`。
- 自动策略不能产生永久封禁；manual 永久封禁只能由经过二次确认的管理操作创建。

### 11.4 Frequency Rule 引用完整性

- 启用 v2 counter namespace 前，所有已启用 frequency rules 都必须具有非空、唯一、稳定且可规范编码的 `rule.id`，不只检查 `cc.rule_ids` 引用的规则。
- `cc.rule_ids` 只允许引用存在且启用、key 为 `"ip"` 或组合 key 明确包含 `"ip"` 的 frequency rules。
- 被引用规则的 `limit`、`window`、matcher 和 key 从现有 frequency rule 读取，不在 kernel section 重复配置。
- 空 `cc.rule_ids` 表示不生成 CC 候选；未知、重复、禁用或不含 IP 维度的引用使整次配置保存失败。
- 修改 frequency rule ID 是显式计数重置操作，API/Dashboard 必须提示 v2 counter 与 CC warm-up 会重新开始。

---

## 12. 管理 API 与 Dashboard

### 12.1 API 草案

建议通过现有 controller 注册体系提供：

| 方法 | 路径草案 | 用途 |
|------|----------|------|
| GET | `/kernel-blocking/status` | Helper、nftables、模式和集合统计 |
| GET | `/kernel-blocking/entries` | 分页查询期望和实际条目 |
| GET | `/kernel-blocking/candidates` | observe 模式候选 |
| POST | `/kernel-blocking/promote` | 人工封禁 |
| POST | `/kernel-blocking/clear` | 人工解除 |
| POST | `/kernel-blocking/reconcile` | 手动触发同步 |
| POST | `/kernel-blocking/pause` | 停止新增晋升 |
| POST | `/kernel-blocking/flush-auto` | 清理自动集合 |

所有 mutating API 必须继承现有：

- Auth
- CSRF
- Rate limit
- Idempotency-Key
- Audit
- 响应大小限制

`GET /kernel-blocking/status` 至少返回：

- `counter_namespace`、`cutover_epoch` 和每条 CC 引用规则的 `warming_up|ready` 状态。
- 控制面 whitelist generation、Helper installed allow generation、canonical digest 和 `allow_refresh_pending`。
- Promotion 桶的配置、当前可用 token、最后补充时间和近期 `rate_limited` 数量。
- dispatch queue 深度、最近 IPC Protocol v1 错误码、table generation 和 reconciliation lease 状态。

### 12.2 Dashboard 草案

建议新增“Kernel Blocking”区域：

- 当前模式：disabled / observe / enforce / degraded
- nftables capability 和 Helper health
- scanner、CC、manual 集合数量
- 最近晋升和解除记录
- 候选 IP、证据和模拟命中数量
- 期望状态与实际状态差异
- Frequency v2 冷切换和 CC warm-up 状态
- 白名单控制面/Helper generation 差异
- 自动晋升桶余额及近期限速拒绝
- 单 IP 详情：来源、TTL、策略版本、历史
- 暂停新增、解除单条、清理自动集合、触发 reconcile

危险操作必须二次确认。Dashboard 不提供任意 nftables 规则编辑器。

---

## 13. 审计与可观测性

### 13.1 指标草案

```text
verynginx_kernel_block_candidates_total{policy,level,result}
verynginx_kernel_block_promotions_total{list,result}
verynginx_kernel_block_entries{list,family,state}
verynginx_kernel_block_operations_total{operation,result}
verynginx_kernel_block_batch_size
verynginx_kernel_block_sync_latency_seconds
verynginx_kernel_block_reconcile_drift
verynginx_kernel_block_queue_dropped_total
verynginx_kernel_block_helper_up
verynginx_kernel_block_allow_generation_lag
verynginx_kernel_block_promotion_tokens
```

其中 `policy` 仅允许 `scanner|cc`，`level` 仅允许 `loose|strict`；被安全门拒绝的原因使用固定枚举，例如 `whitelisted|topology|family|scope|capacity|challenge_required|rate_limited|warming_up`。counter namespace、cutover epoch 和 generation 具体值优先通过 status 返回，不把 IP、rule ID、generation 或自由文本作为 Prometheus label，防止高基数。

### 13.2 审计字段

- 操作者或 `system`
- IP 和地址族
- 集合
- 操作：candidate/promote/install/clear/expire
- 原因和证据摘要
- 证据记录、策略评估、IPC 派发和 nft 安装各自的阶段与时间
- TTL 和到期时间
- 策略版本
- Helper/nftables 结果
- request ID 或 batch ID

### 13.3 日志

- 批量操作优先记录汇总。
- 单 IP 详细事件进入有界审计存储。
- 相同错误做采样和抑制。
- Protocol v1 不引入应用层共享 IPC 密钥。日志不得记录完整白名单 snapshot、敏感配置、未批准的 peer credential 细节、完整请求 payload 或原始 nft 输出。

---

## 14. 失败策略与紧急恢复

### 14.1 Fail-open

以下故障不得导致 Nginx 无法启动或正常请求被默认拒绝：

- Helper 未安装或未运行
- Socket 权限错误
- nftables 不可用或 capability probe 失败
- 集合达到容量
- IPC 超时
- reconciliation 失败
- 内核规则被外部删除
- 自动晋升令牌桶状态损坏或不可用

故障时：

1. 停止新的内核晋升。
2. 标记状态为 degraded。
3. 保留现有 Lua WAF、声誉和频率限制。
4. 指标和日志告警。
5. Helper 恢复后后台 reconcile。

令牌桶故障只暂停新的自动内核晋升，不能影响现有 Lua WAF、手动解除、白名单刷新或已接受期望状态的 reconciliation。

### 14.2 紧急操作

必须支持相互独立的动作：

- `pause promotion`：停止新增，不动现有集合。
- `flush auto`：清理 scanner/CC 自动集合，保留 manual。
- `flush all owned`：清理全部 VeryNginx 自有集合。
- `detach chain`：从系统 hook 移除 VeryNginx 自有 jump/chain。
- `disable config`：下次启动保持关闭。

### 14.3 管理员逃生通道

- 保留云控制台或宿主机控制台。
- 记录本地只读诊断和清理命令。
- 管理 API 不能是唯一解除手段。
- 管理出口、SSH 来源和健康检查来源应加入现有 `ip_reputation.whitelist`。
- Helper 必须拒绝任何针对 `ip_reputation.whitelist`、运行时自动白名单、Unix Socket 对端和内建本机/保留地址的 DROP 请求，包括 `manual_drop`；普通管理 API 不提供绕过能力。

---

## 15. 部署模型

### 15.1 裸机或 systemd

首期正式支持范围以配套 LNMP 脚本声明为准，只覆盖最近两个 Debian/Ubuntu 版本。LNMP 安装流程负责：

- 使用发行版包管理器安装 nftables 用户态工具。
- 运行第 9.6 节 capability probe。
- 安装 Helper、systemd unit 和 Unix Socket 权限。
- 检测 UFW、Docker、`iptables-nft` 和已有 `table inet verynginx`。
- 不覆盖用户的 `/etc/nftables.conf`，不清空已有 nftables table。
- capability 不满足时保持 Lua WAF 可用，并明确报告内核封禁不可用。
- 首次引入 Frequency Counter Key v2 时执行 OpenResty 冷重启，不使用 graceful reload 混跑旧、新 key；发布说明明确所有活动限频窗口重置以及 CC 证据 warm-up。

推荐模型：

```text
openresty.service        普通 nginx 用户
verynginx-firewall.service  最小 capability
Unix Socket              nginx 组可写，其他用户不可访问
```

Helper 应在防火墙就绪后启动。OpenResty 不应强依赖 Helper 启动成功。

### 15.2 Docker

容器内修改防火墙通常只影响容器网络命名空间，不一定保护宿主机入口。推荐：

- Helper 运行在宿主机。
- VeryNginx 容器通过受限挂载的 Unix Socket 提交事件。
- 不给主容器 `--privileged`。
- 不给主容器 `NET_ADMIN`。
- 若使用 sidecar，必须明确其网络命名空间和实际 hook 位置。

默认 Docker 模式只允许 `observe`，除非部署检查确认执行面位于正确网络命名空间。

### 15.3 Kubernetes

首期不承诺支持。Pod 内规则通常无法替代 Node、Ingress 或云边缘防护。未来应评估：

- DaemonSet Helper
- CNI/eBPF 集成
- NetworkPolicy
- Ingress/CDN API

这些能力不应混入首期本机 nftables 实现。

---

## 16. 测试与验收

### 16.1 单元测试

- scanner/CC promotion policy
- Promotion 不作为普通 access plugin，terminal action 后不合成后续插件证据
- scanner block 分槽计数、原子递增、TTL、窗口汇总和有界索引
- CC rule ID 引用校验、IP key 限制、v2 key 无歧义编码和每个原始计数生命周期一次的超限证据
- v2 冷切换隔离旧 key、统一 cutover epoch、warm-up、修改 rule ID 和 rollback 重置语义
- 白名单和 protected address 优先级
- generation-qualified 白名单正负缓存、CIDR 变更、静态 add/remove、配置整体替换、保存失败和旧 generation 自然过期
- 自动白名单创建、删除、过期和缓存 TTL 不越过 auto-allow 到期时间
- 白名单覆盖 manual/scanner/CC，以及完整 snapshot 高优先级 allow 刷新
- scanner/CC 重叠时的单一自动集合归属
- 全局自动晋升令牌桶 burst/refill、scanner/CC 共享、升级、续期、重复证据、observe 虚拟桶、reload 状态保留和 manual 排除
- TTL 分级和最大值
- IPv4/IPv6 解析、规范化和非法输入
- 拓扑安全门
- 状态机转换
- 队列去重、容量和过期
- 递归配置默认值、部分嵌套对象、未知字段、map/array 形状、错误类型和规范化后的跨字段验证
- scheduler 唯一所有权、自重调度、热加载 interval、lease 过期、premature、无重复注册和 worker 退出持久化

### 16.2 Nft Executor Contract Test

固定 nftables Executor 必须通过以下契约：

- `ensure_base` 幂等
- 重复 add
- delete 不存在条目
- TTL 到期
- IPv4/IPv6 隔离
- nftables interval allow set 对精确 IP、CIDR、IPv4 和 IPv6 的行为
- 批量原子性或明确的部分失败语义
- list 分页
- flush 只影响自有对象
- 外部删除后的 reconcile
- `/usr/sbin/nft` 缺失、超时、非零退出和畸形 JSON 输出的错误映射

### 16.3 IPC Protocol v1 Contract Test

- 4 字节 framing、截断、超限、无效 UTF-8、尾随值和多个 JSON 值
- 请求/响应 envelope、request ID 回显和固定错误码 retryable 属性
- 每个操作的 schema、未知字段拒绝、批量上限和 request 级 all-or-nothing
- 相同 request ID 重放、不同摘要冲突、timeout 后同 ID 重试和幂等缓存容量
- protocol/capability 协商、不兼容 major version 和未知安全字段
- whitelist/desired/table generation 过期、冲突和在途旧 snapshot 不能覆盖新状态
- whitelist epoch bootstrap 前合并刷新请求，`ensure_base` 成功后只发送最新完整 snapshot
- reconcile snapshot 分块顺序、final chunk 前禁止权威删除、缺块/超时中止和 generation pinning
- list cursor 在 table generation 变化后失效
- 持久连接生命周期、单 in-flight、timeout、EOF、Helper 重启、退避和有界队列
- Unix peer credentials、Socket owner/mode、stale socket 和非授权本地用户
- Helper DROP add/renew hard limit、IPC request limit 与 batch limit 互不混淆，伪造 `source=manual` 不能绕过

### 16.4 Linux 集成测试

使用 network namespace 或专用 CI runner 验证：

- 命中集合的包无法到达测试 Nginx。
- 未命中流量正常通过。
- allow 使用 RETURN，不绕过其他系统规则。
- allow 更新无需等待周期 reconciliation，并优先覆盖 manual/scanner/CC。
- Helper 确认某个 allow generation 后，该 snapshot 覆盖的地址不再存在于任何自有 DROP set。
- 同一来源访问未保护端口时不被自动集合拦截。
- 转发流量、UDP 和 SSH 默认不受 Web 作用域规则影响。
- raw/prerouting 位置符合预期。
- conntrack、Docker 和防火墙管理器交互。
- Helper 无权限时 fail-open。
- Helper crash/restart 后恢复。
- v2 升级和回滚冷切换不会把旧 key 当作新计数或 CC 证据。

### 16.5 安全测试

- IPC 命令注入
- 超长消息和畸形 JSON
- 非法集合名、地址、TTL
- 非授权本地用户访问 Socket
- 伪造 `X-Forwarded-For`
- CDN 节点误封保护
- 管理地址和本机地址保护
- 大批量事件导致的内存、CPU 和日志放大
- IPC replay、generation downgrade、request ID 冲突、cursor 滥用和连接耗尽

### 16.6 性能测试

至少比较：

1. 无防护基线。
2. Lua WAF 403。
3. filter INPUT DROP。
4. raw/prerouting set DROP。
5. 1 千、10 万、100 万集合条目下的查找和更新成本。

关注：

- PPS
- Nginx worker CPU
- TLS 握手数
- 活跃连接数
- conntrack 使用
- Helper 批处理延迟
- reconciliation 耗时
- 内存占用

---

## 17. 分阶段实施建议

| 阶段 | 内容 | 是否写内核 | 退出条件 |
|------|------|------------|----------|
| Phase 0 | 威胁模型、递归配置 schema、默认值/跨字段验证、IPC v1、Executor contract、调度 wiring、独立快照格式 | 否 | 设计评审和 contract test 方案通过 |
| Phase 1 | Frequency Counter Key v2 冷切换、证据采集、Promotion Policy observe-only、虚拟晋升桶 | 否 | warm-up 完成，候选数据稳定，无明显误判 |
| Phase 2 | nftables Executor、Helper、IPC v1、只读 probe/list | 否 | 权限、capability、协议和故障测试通过 |
| Phase 3 | Shadow reconciliation | 否或隔离 namespace | 期望/实际差异可解释 |
| Phase 4 | nftables 小流量 canary，短 TTL | 是 | 误封率和回滚指标达标 |
| Phase 5 | LNMP 安装集成、UFW/Docker 共存验证 | 是 | 支持矩阵和升级路径明确 |
| Phase 6 | Dashboard/API 与正式启用 | 是 | 运维手册、监控和逃生通道完备 |

### Phase 1 建议重点

observe 模式先回答：

- 每天产生多少 scanner 和 CC 候选？
- 候选中是否包含管理员、搜索引擎、监控或共享出口？
- 候选持续时间和重复率如何？
- 采用不同 TTL 和阈值时模拟阻断量如何？
- 最大集合规模和每秒新增速率是多少？
- 全局晋升桶在候选数据上会拒绝多少 `would_promote`，scanner 与 CC 是否互相挤占？

Phase 1 开始前必须完成 Frequency Counter Key v2 冷重启切换并记录统一 `cutover_epoch`。CC 数据只统计切换后产生的 violation marker；warm-up 完成前不得把历史不足误判为策略安全。

Scanner 必须同时统计两个层次：

```text
loose:
  window 内 min_hard_blocks >= 1
  用于观察所有可能进入晋升漏斗的来源

strict:
  已 flagged
  AND window 内 min_hard_blocks >= 3
  AND 通过白名单、拓扑、地址族、保护作用域、容量和虚拟速率安全门
  等价于 enforce 模式实际会安装的候选
```

CC 同样记录“首次被引用规则超限”的 loose 指标，以及满足 `min_violation_windows`、Challenge 要求和全部安全门的 strict 指标。指标按 IP、策略和证据窗口去重，但不能把 IP 或 rule ID 作为 Prometheus label；阈值分布可使用固定 bucket，例如 block 命中数 `1/2/3/5/10+`。

在没有这些数据之前，不应决定 enforce 默认阈值。

---

## 18. 非目标与能力边界

本方案不负责：

- 替代 WAF、Challenge、IP reputation 或 frequency limit
- 防御已经占满公网带宽的大规模 DDoS
- 自动封禁网段、ASN、国家或 CDN 节点
- 跨主机分布式黑名单同步
- 管理云安全组、CDN ACL 或 Kubernetes NetworkPolicy
- 提供通用主机防火墙编辑器
- 保证识别每 IP 低频的大规模分布式 CC
- 处理攻击者快速轮换 IPv6 地址或代理池的全部场景

如果攻击已经在到达主机前占满链路，本机 DROP 无法恢复带宽，需要上游清洗、CDN、Anycast 或运营商协作。

---

## 19. 待决策事项

1. Helper 使用何种实现语言和进程模型？
2. 配套 LNMP 当前支持的 Debian/Ubuntu 版本分别对应哪些最低 kernel 和 nftables 版本？
3. Helper 首期使用 `/usr/sbin/nft` 子进程、libnftables 还是直接 Netlink？
4. scanner 和 CC 的初始晋升阈值如何通过 observe 数据确定？
5. 是否允许按重复攻击阶梯式延长 TTL？
6. Docker 首期是否只支持宿主机 Helper？
7. IPv6 单地址封禁何时默认开启？
8. 是否永远禁止自动 IPv6 `/64` 聚合，还是保留实验开关？
9. 与 UFW、`iptables-nft`、Docker 和用户已有 nftables table 的支持矩阵如何定义？
10. 是否需要未来对接 CDN/云防火墙 API；若需要，应设计为独立边缘执行层，而不是本机防火墙 backend？

---

## 总结

内核层 IP 封禁适合作为 VeryNginx 的二级执行层：

```text
应用层检测和积累证据
  -> 独立晋升策略
  -> 特权 Helper
  -> nftables 临时集合
```

其核心价值是减少已确认恶意来源的重复处理成本。其主要风险是误封、代理/CDN 拓扑误判、权限扩大和防火墙状态漂移。因此首期必须坚持：

- 默认关闭
- observe 先行
- 短 TTL
- scanner 与 CC 分集合
- 不在 worker 中执行 shell
- Helper 最小权限
- 白名单和管理地址双重保护
- CDN/代理场景默认禁止 enforce
- fail-open
- 可审计、可回滚、可 reconciliation

只有在 observe 数据证明晋升策略稳定、网络拓扑明确、紧急恢复路径经过验证后，才进入 enforce 阶段。
