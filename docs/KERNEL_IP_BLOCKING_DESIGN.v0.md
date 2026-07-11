# VeryNginx 内核层 IP 封禁设计草案

> **版本**: Draft v0.1  
> **日期**: 2026-07-11  
> **状态**: 讨论阶段，尚未实现  
> **适用范围**: Linux 直连源站，候选后端为 nftables 或 ipset/iptables

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
9. [防火墙后端抽象](#9-防火墙后端抽象)
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
5. **后端可替换**：业务层不直接依赖 nftables 或 ipset/iptables 的命令格式。
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

- nftables 或 ipset/iptables 后端
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

请求处理仅记录信号或候选事件，不执行以下操作：

- `os.execute`
- `io.popen`
- `nft`、`ipset`、`iptables` 命令
- 同步 Unix Socket 请求
- 防火墙状态全量读取或 reconciliation

候选事件由定时批处理或异步本地通道交给 Helper。

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
- 后端切换和策略升级必须支持 observe/shadow 阶段。

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
│  参数校验 -> 白名单保护 -> 去重/限额 -> Backend Adapter  │
│                       │                                  │
│                 Reconciler / Health                      │
└───────────────────────┼──────────────────────────────────┘
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
        nftables backend    ipset/iptables backend
              │                   │
              └─────────┬─────────┘
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

- 接收 WAF、声誉和频率限制信号。
- 根据 scanner/CC 独立策略产生候选和晋升决定。
- 复用现有 `ip_reputation.whitelist` 和自动白名单，执行地址合法性和拓扑安全检查。
- 生成原因、TTL、策略版本和证据摘要。
- 不直接写防火墙。

#### Firewall Helper

- 验证 IPC 请求。
- 管理固定名称的集合和链。
- 执行幂等 add/delete/list/health/reconcile。
- 控制最大条目数、TTL 范围和允许的地址族。
- 返回结构化结果，不返回原始命令输出。

#### Reconciler

- 比较期望状态与实际内核状态。
- 补装缺失条目，移除已过期或不再期望的条目。
- 检测链或集合被外部删除、规则顺序变化和容量异常。
- 在后台运行，不阻塞请求。

---

## 5. 集合与状态模型

### 5.1 建议集合

| 逻辑集合 | 来源 | 默认生命周期建议 | 说明 |
|----------|------|------------------|------|
| `scanner_drop` | 高置信 WAF/声誉晋升 | 初始复用 `ip_reputation.flag_duration`（当前默认 600 秒），重复晋升可分级延长 | 处理漏洞扫描、目录扫描、RCE/SQLi 重复探测 |
| `cc_drop` | 持续频率违规和 Challenge 失败 | 1 至 10 分钟 | 短 TTL，降低 NAT/CGNAT 误封影响 |
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

逻辑集合在后端中至少拆分为：

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
- IPv4 和 IPv6 后端故障互不影响。
- IPv6 前缀聚合默认关闭。
- 当前 IP 声誉 CIDR 匹配能力以 IPv4 为主，不能假设已有完整 IPv6 白名单能力。

### 5.3 生命周期

```text
observed
   │ 达到候选条件
   ▼
candidate
   │ 达到晋升条件，且通过安全检查
   ▼
promoted
   │ Helper 成功写入
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
6. 未超过集合容量和单位时间晋升上限。
7. 候选证据仍在有效窗口内。

### 6.2 Scanner 晋升

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

### 6.3 CC 晋升

CC 的误封风险高于 scanner，尤其是 NAT、校园网、企业出口和移动网络。建议采用渐进流程：

```text
应用层超限
  -> 429/Challenge
  -> 连续多个窗口超限
  -> Challenge 多次失败或请求行为持续恶化
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

现有限频原始计数 key 也必须加入 rule ID，避免两条使用相同 `key` 维度的规则互相污染：

```text
fl:count:<rule_id>:<built_dimension_key>
```

超限窗口证据复用 `lua_shared_dict frequency_limit`，建议 key：

```text
fl:kernel:violation:<rule_id>:<ip>:<evidence_slot>
```

其中：

- 保留现有限频“计数 key 首次创建后按 `rule.window` TTL 过期”的窗口语义，不改成对齐时间槽。
- 晋升证据单独使用 `evidence_slot = floor(ngx.time() / rule.window)`，它只用于把超限事件归入稳定、可汇总的观察槽，不改变原始限频行为。
- 当 `current == rule.limit + 1` 时用 `shared:add()` 写入当前 slot marker；后续同一原始计数生命周期中 `current` 更大，不会重复记录。
- 若两个固定 TTL 计数生命周期在边界情况下落入同一 evidence slot，`shared:add()` 会保守合并为一次证据，不会重复放大晋升计数。
- TTL 至少为 `rule.window × (cc.min_violation_windows + 1)`，确保最早证据在评估窗口内仍可读取。
- Promotion Policy 只统计仍未过期的证据 marker。
- 维护有界的 CC 候选索引，不能依赖 `/frequency/stats` 或 `get_keys()` 枚举。
- 计数 key 和证据 key 都不写持久化快照；流量恢复后可重新生成。

从旧 `fl:*` key 迁移到包含 rule ID 的格式会自然重置当前限频窗口，应在 reload/升级说明中明确。不能从旧原始计数反推出连续超限窗口。

初始策略示意：

```text
条件 A：至少一个被引用的 IP 限频规则发生超限
AND 条件 B：达到 min_violation_windows 个超限证据窗口
AND 条件 C：若 require_challenge_fail=true，则观察期内存在 challenge_fail
THEN：晋升 cc_drop
```

建议的附加判断包括：

- 连续或近期多个证据窗口超过 frequency limit
- 达到最小观测时长
- 已经由 Nginx 拒绝足够次数
- Challenge 失败或无正常会话行为
- 请求速率显著高于正常峰值
- 不在白名单、可信代理和健康检查列表

不建议只依据瞬时 QPS 自动进入内核集合。正常流量突发应优先由 Nginx 限流吸收。

`min_violation_windows=3` 和 `require_challenge_fail=true` 是新的晋升策略参数，不是现有 frequency rule 默认值。它们必须在 observe 阶段同时评估宽松和严格结果后校准；首期 enforce 不应在没有候选数据时把示例值视为经过验证的安全默认值。`rule_ids` 为空时不产生任何 CC 候选。

### 6.4 手动封禁

人工操作必须要求：

- 已认证管理员
- CSRF 验证
- 审计日志
- 明确集合、原因和 TTL
- 永久封禁需二次确认
- 禁止封禁本机、管理出口和受保护地址
- 静态或自动白名单覆盖所有人工 DROP；普通 manual 操作不能强制绕过白名单

### 6.5 续期与降级

- 同一 IP 重复晋升时不无限叠加 TTL。
- 每次续期记录原因和策略版本。
- 达到最大封禁时长后仍持续攻击，可提升到更长等级，但不能自动转永久。
- Helper 故障时保留 Lua 层 flagged/limit 行为，不将同步失败视为已安装。
- `ip_reputation.whitelist` 或自动白名单新增后应尽快撤销对应自动封禁并刷新执行面的 `allow` 快照。

白名单新增属于高优先级安全事件，不能等待默认 30 秒 reconciliation：

1. 静态白名单先通过现有 `config.save()` 成功持久化。
2. 原子递增白名单 generation，使 Lua 层 `is_whitelisted()` 的旧正/负缓存立即失效。现有固定 `ip_rep:wl_cache:<ip>` 需要改为携带 generation 或使用 generation 前缀，CIDR 变更不能依赖逐个删除缓存 key。
3. 控制面将规范化地址/CIDR 写入高优先级本地队列。
4. 当前请求所在 worker 使用 `ngx.timer.at(0, ...)` 或等价异步机制立即向 Helper 发送带 whitelist generation 和幂等 request ID 的固定 allow 刷新请求，不阻塞 API 请求等待 Helper。Helper 负责串行化和去重；不能假设该 timer 会运行在 worker 0。
5. Helper 先更新 `allow` 集合，再移除被覆盖的 `scanner_drop`、`cc_drop` 和 `manual_drop` 条目。
6. 相关期望状态记录 `whitelist_override`；人工条目进入 `suppressed_by_allow`，自动条目清除。
7. 运行时自动白名单创建时同样失效对应 Lua 白名单缓存，并走高优先级 allow 刷新路径。
8. worker 0 的周期 reconciliation 继续作为丢事件、重复事件或 Helper 暂时不可用时的兜底。

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
- `X-Forwarded-For` 中的真实客户端 IP 无法被本机 ipset/nftables 直接匹配。
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
| `auto` | 仅检测明显风险并告警，不自动假定安全 |

不能仅靠应用层自动推断网络拓扑后直接启用 enforce。

---

## 8. 权限分离与 Helper

### 8.1 禁止 worker 直接执行系统命令

不采用以下实现：

```lua
os.execute("ipset add ...")
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

### 8.3 IPC 草案

建议使用本地 Unix Domain Socket：

```text
/run/verynginx/firewall-helper.sock
```

请求必须是长度受限、版本化的结构化消息，例如：

```json
{
  "version": 1,
  "request_id": "01J...",
  "operation": "add",
  "list": "scanner_drop",
  "ip": "203.0.113.10",
  "family": "ipv4",
  "ttl": 3600,
  "reason": "repeated_hard_block"
}
```

允许操作限定为：

```text
probe
ensure_base
add
delete
list
health
reconcile
flush_owned
```

Helper 必须执行：

- 消息长度限制
- JSON schema 或等价严格验证
- IP 解析和规范化
- 固定集合名枚举
- 固定协议、目标地址和目标端口作用域
- 根据控制面下发的 `ip_reputation.whitelist` 规范化快照拒绝封禁；该快照只能收紧 Helper 可执行范围，不能由单次 add 请求覆盖
- TTL 上下限
- 每批操作数量限制
- Socket 文件权限检查
- 调用方身份检查
- 超时与速率限制

---

## 9. 防火墙后端抽象

### 9.1 统一接口

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

业务策略不得出现 `nft`、`ipset` 或 `iptables` 命令文本。

### 9.2 nftables 后端

建议使用独立的 VeryNginx table、chain 和带 timeout 的 set。概念结构：

```text
table inet verynginx
  set allow_v4        type ipv4_addr, flags interval
  set allow_v6        type ipv6_addr, flags interval
  set scanner_drop_v4 type ipv4_addr, flags timeout
  set scanner_drop_v6 type ipv6_addr, flags timeout
  set cc_drop_v4      type ipv4_addr, flags timeout
  set cc_drop_v6      type ipv6_addr, flags timeout
  set manual_drop_v4  type ipv4_addr
  set manual_drop_v6  type ipv6_addr
  chain prerouting    hook prerouting, priority raw
```

要求：

- 使用原子 transaction 更新批次。
- 对自动集合使用内核 timeout。
- `allow` 集合由现有 `ip_reputation.whitelist` 和运行时自动白名单派生；静态 CIDR 必须按后端支持的区间/前缀语义加载。
- 只管理 `table inet verynginx`。
- 安装前检查同名对象是否由本系统创建。
- 删除时只删除自有对象。

### 9.3 ipset/iptables 后端

建议：

- `allow_v4` 和 `allow_v6` 使用 `hash:net`，分别指定 `family inet` 和 `family inet6`。
- 静态精确 IP 规范化为 `/32` 或 `/128`，CIDR 保持网段形式写入 `hash:net`，不展开成大量单 IP。
- `scanner_drop`、`cc_drop` 和首期 `manual_drop` 使用 `hash:ip`；自动集合启用 timeout。
- 独立 `allow` 集合在所有 DROP 集合前匹配，因此不需要依赖 `nomatch`。若未来合并集合，才评估 `hash:net nomatch` 方案。
- IPv4 与 IPv6 分离。
- 使用固定自有链，从 `raw PREROUTING` 跳转。
- 重复安装 jump rule 时保持幂等。
- 使用 `ipset restore` 等批量方式，避免一条记录一个进程。
- 清理时只移除自有 jump、chain 和 set。

### 9.4 规则位置

优先考虑在 conntrack 和 Nginx 之前丢弃，但实际 hook/priority 必须经过不同发行版和现有防火墙管理器验证。

规则至少还要匹配配置的保护作用域：

- 目标地址属于本机受保护监听地址
- 协议为 TCP
- 目标端口属于 `protected_ports`
- 默认不匹配转发流量

不能只按源 IP 在整个 `PREROUTING` 上无条件 DROP，否则可能同时阻断该 IP 对 SSH、数据库或同机其他服务的访问。是否提供 `host_wide` 模式属于后续独立决策。

需兼容或明确不兼容：

- firewalld
- ufw
- Docker 自动生成的 iptables 规则
- Kubernetes/CNI
- 云主机安全代理

任何情况下都不能假设 VeryNginx 是系统唯一防火墙管理者。

### 9.5 后端选择

建议配置：

- `nftables`：新系统首选。
- `ipset`：兼容旧系统。
- `auto`：只做 capability probe 并报告建议，不在首期自动迁移已有规则。

后端切换必须先停止新增、导出期望状态、初始化新后端、shadow 对比，再切换执行链。

---

## 10. 一致性、持久化与恢复

### 10.1 期望状态与实际状态

- **期望状态**：VeryNginx 判断应该处于封禁状态的条目。
- **实际状态**：当前内核集合中的条目。

API 和 Dashboard 必须区分：

```text
promoted but not installed
installed
expired
drifted
helper unavailable
```

不能在事件发送成功前就显示为 installed。

### 10.2 批处理

- 同 IP、同集合的短时间重复事件合并。
- 批量发送给 Helper。
- 自动集合以 `expires_at` 为准，Helper 转换为剩余 TTL。
- 过期事件不再安装。
- 队列必须有容量上限，溢出时记录指标并继续由 Lua WAF 防护。

### 10.3 持久化建议

复用现有 `core.init` 的 worker 0 持久化调度机制，但保持状态文件和模块职责独立：

```text
core.init.init()
  ├─ ip_reputation.restore()
  └─ kernel_blocking.restore()

core.init.init_worker() / worker 0
  ├─ 每 600 秒:
  │    ├─ ip_reputation.persist()
  │    └─ kernel_blocking.persist()
  └─ worker 退出轮询:
       ├─ ip_reputation.persist()
       └─ kernel_blocking.persist()
```

现有 IP 声誉状态继续写入：

```text
configs/ip-reputation-flagged.json
```

内核封禁期望状态使用独立文件：

```text
configs/kernel-blocking-state.json
```

不把两类状态合并进同一 JSON，原因是它们的 schema、版本、生命周期和失败恢复语义不同。`kernel_blocking.persist()` 自身不注册定时器，也不创建第二套 worker 0 调度；定时器和退出轮询统一由 `core.init` 注册，避免多 worker 或重复 timer 并发写文件。

快照要求：

- 使用版本化 payload。
- 保存 promoted/installed 期望状态、人工封禁及绝对 `expires_at`，不保存可重建的短期请求队列。
- 使用同目录临时文件加原子 rename。
- `persist()` 内仍保留 worker 0 防御性检查，与现有 `ip_reputation.persist()` 一致。
- 启动恢复时丢弃已经过期的自动条目，并按 `expires_at - now` 计算剩余 TTL，不能重新赋予完整 TTL。
- 人工永久封禁和未过期人工 TTL 封禁必须恢复。
- 快照缺失、损坏或版本不支持时 fail-open，记录告警但不阻断 Nginx 启动。
- 恢复只建立期望状态，不直接假定内核已安装；进入 `init_worker` 后由 worker 0 触发 Helper reconciliation。

候选和短期批处理队列保留在内存中，不在每次请求中同步写文件。若生产规模证明独立 JSON 快照不足，再评估 SQLite 或 Helper 自有存储。

### 10.4 Reconciliation

由单一调度者执行。Lua 侧复用 `core.init` 的 worker 0 调度，不由 `kernel_blocking` 模块自行注册 timer。建议流程：

1. 读取 Helper health 和后端 generation。
2. 分页读取自有集合实际状态。
3. 与未过期的期望状态比较。
4. 批量补装缺失条目。
5. 删除不再期望且由自动策略创建的条目。
6. 保留无法确认所有权的外部条目并告警。
7. 记录耗时、差异数量和失败原因。

---

## 11. 配置草案

以下仅表达字段形状。Scanner 基础阈值和初始 TTL 复用现有 `ip_reputation` 运行时配置；CC、容量和重复晋升上限等新参数仍需经过 observe 数据和测试确定：

```json
{
  "kernel_ip_blocking": {
    "enabled": false,
    "mode": "observe",
    "backend": "nftables",
    "topology": "direct",
    "fail_policy": "open",
    "helper_socket": "/run/verynginx/firewall-helper.sock",
    "scope": "web",
    "protected_addresses": [],
    "protected_ports": [80, 443],
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
    "promotion_rate_limit": 1000
  }
}
```

### 11.1 Schema 要求

- 必须正式加入 `core/config.lua` schema。
- 嵌套字段必须填充默认值，不能依赖完整配置才安全。
- 对枚举、TTL、容量、路径和整数范围做验证。
- `fail_policy` 首期只允许 `open`。
- `topology != direct` 时拒绝保存 `mode=enforce`。
- `scope` 首期只允许 `web`，`protected_ports` 必须显式且非空。
- `protected_addresses` 表示受内核规则保护的本机目标地址，不是来源白名单。空数组只允许 `disabled` 或 `observe`；保存或激活 `mode=enforce` 时必须拒绝空数组。
- 首期不自动推断接口地址，也不把空数组解释为所有本机地址。enforce 必须显式列出规范化的本机单播目标地址，Helper `ensure_base()` 也要独立拒绝空作用域。
- 不新增 `never_block_addresses` 或其他并行来源白名单；静态来源白名单统一复用 `ip_reputation.whitelist`。
- Helper 和内核 `allow` 集合使用 `ip_reputation.whitelist` 的规范化快照。运行时自动白名单作为附加的临时 allow 状态同步，不要求用户重复配置。
- Scanner 的总分阈值、最少请求数、证据窗口、`waf_block` 权重和初始 TTL 分别读取 `ip_reputation.threshold`、`min_requests`、`window_size`、`signals.waf_block` 和 `flag_duration`，不得在本 section 重复配置。
- `scanner.min_hard_blocks` 只统计产生 `waf_block` 信号的 `action="block"` 命中，是独立证据门槛，不是附加到 `ip_reputation.threshold` 上的分数。
- `cc.rule_ids` 只允许引用已启用且 key 包含 IP 的现有 frequency rules；`limit`、`window`、matcher 和 key 定义从规则读取，不在 kernel section 重复配置。空 `rule_ids` 表示禁用 CC 候选生成。
- `cc.min_violation_windows` 和 `require_challenge_fail` 是待 observe 校准的新晋升门槛，不属于现有限频规则默认值。
- `ipv6.prefix_aggregation=true` 首期应拒绝或仅允许实验模式。
- `manual` 永久封禁不得由自动策略配置产生。

---

## 12. 管理 API 与 Dashboard

### 12.1 API 草案

建议通过现有 controller 注册体系提供：

| 方法 | 路径草案 | 用途 |
|------|----------|------|
| GET | `/kernel-blocking/status` | Helper、后端、模式、集合统计 |
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

### 12.2 Dashboard 草案

建议新增“Kernel Blocking”区域：

- 当前模式：disabled / observe / enforce / degraded
- Backend 和 Helper health
- scanner、CC、manual 集合数量
- 最近晋升和解除记录
- 候选 IP、证据和模拟命中数量
- 期望状态与实际状态差异
- 单 IP 详情：来源、TTL、策略版本、历史
- 暂停新增、解除单条、清理自动集合、触发 reconcile

危险操作必须二次确认。Dashboard 不提供任意 nftables/iptables 编辑器。

---

## 13. 审计与可观测性

### 13.1 指标草案

```text
verynginx_kernel_block_candidates_total{policy,level,result}
verynginx_kernel_block_promotions_total{list,result}
verynginx_kernel_block_entries{list,family,state}
verynginx_kernel_block_operations_total{backend,operation,result}
verynginx_kernel_block_batch_size
verynginx_kernel_block_sync_latency_seconds
verynginx_kernel_block_reconcile_drift
verynginx_kernel_block_queue_dropped_total
verynginx_kernel_block_helper_up
```

其中 `policy` 仅允许 `scanner|cc`，`level` 仅允许 `loose|strict`；被安全门拒绝的原因使用固定枚举，例如 `whitelisted|topology|family|scope|capacity|challenge_required`。避免把 IP、rule ID 或自由文本作为 Prometheus label，防止高基数。

### 13.2 审计字段

- 操作者或 `system`
- IP 和地址族
- 集合
- 操作：candidate/promote/install/clear/expire
- 原因和证据摘要
- TTL 和到期时间
- 策略版本
- Helper/backend 结果
- request ID 或 batch ID

### 13.3 日志

- 批量操作优先记录汇总。
- 单 IP 详细事件进入有界审计存储。
- 相同错误做采样和抑制。
- 不记录 IPC 密钥或敏感配置。

---

## 14. 失败策略与紧急恢复

### 14.1 Fail-open

以下故障不得导致 Nginx 无法启动或正常请求被默认拒绝：

- Helper 未安装或未运行
- Socket 权限错误
- nftables/ipset 不可用
- 集合达到容量
- IPC 超时
- reconciliation 失败
- 内核规则被外部删除

故障时：

1. 停止新的内核晋升。
2. 标记状态为 degraded。
3. 保留现有 Lua WAF、声誉和频率限制。
4. 指标和日志告警。
5. Helper 恢复后后台 reconcile。

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

这些能力不应混入首期本机 nftables/ipset 实现。

---

## 16. 测试与验收

### 16.1 单元测试

- scanner/CC promotion policy
- scanner block 分槽计数、原子递增、TTL、窗口汇总和有界索引
- CC rule ID 引用校验、IP key 限制和每个原始计数生命周期一次的超限证据
- 白名单和 protected address 优先级
- 白名单覆盖 manual/scanner/CC，以及高优先级 allow 刷新
- scanner/CC 重叠时的单一自动集合归属
- TTL 分级和最大值
- IPv4/IPv6 解析、规范化和非法输入
- 拓扑安全门
- 状态机转换
- 队列去重、容量和过期
- 配置 schema 与不安全组合拒绝

### 16.2 Backend Contract Test

所有后端必须通过同一套契约：

- `ensure_base` 幂等
- 重复 add
- delete 不存在条目
- TTL 到期
- IPv4/IPv6 隔离
- ipset `hash:net` allow 对精确 IP、CIDR、IPv4 和 IPv6 的行为
- 批量原子性或明确的部分失败语义
- list 分页
- flush 只影响自有对象
- 外部删除后的 reconcile

### 16.3 Linux 集成测试

使用 network namespace 或专用 CI runner 验证：

- 命中集合的包无法到达测试 Nginx。
- 未命中流量正常通过。
- allow 使用 RETURN，不绕过其他系统规则。
- allow 更新无需等待周期 reconciliation，并优先覆盖 manual/scanner/CC。
- 同一来源访问未保护端口时不被自动集合拦截。
- 转发流量、UDP 和 SSH 默认不受 Web 作用域规则影响。
- raw/prerouting 位置符合预期。
- conntrack、Docker 和防火墙管理器交互。
- Helper 无权限时 fail-open。
- Helper crash/restart 后恢复。

### 16.4 安全测试

- IPC 命令注入
- 超长消息和畸形 JSON
- 非法集合名、地址、TTL
- 非授权本地用户访问 Socket
- 伪造 `X-Forwarded-For`
- CDN 节点误封保护
- 管理地址和本机地址保护
- 大批量事件导致的内存、CPU 和日志放大

### 16.5 性能测试

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
| Phase 0 | 威胁模型、配置 schema、backend contract、独立快照格式 | 否 | 设计评审通过 |
| Phase 1 | Promotion Policy observe-only | 否 | 候选数据稳定，无明显误判 |
| Phase 2 | Helper、IPC、只读 probe/list | 否 | 权限和故障测试通过 |
| Phase 3 | Shadow reconciliation | 否或隔离 namespace | 期望/实际差异可解释 |
| Phase 4 | nftables 小流量 canary，短 TTL | 是 | 误封率和回滚指标达标 |
| Phase 5 | ipset/iptables 兼容后端 | 是 | backend contract 全绿 |
| Phase 6 | Dashboard/API 与正式启用 | 是 | 运维手册、监控和逃生通道完备 |

### Phase 1 建议重点

observe 模式先回答：

- 每天产生多少 scanner 和 CC 候选？
- 候选中是否包含管理员、搜索引擎、监控或共享出口？
- 候选持续时间和重复率如何？
- 采用不同 TTL 和阈值时模拟阻断量如何？
- 最大集合规模和每秒新增速率是多少？

Scanner 必须同时统计两个层次：

```text
loose:
  window 内 min_hard_blocks >= 1
  用于观察所有可能进入晋升漏斗的来源

strict:
  已 flagged
  AND window 内 min_hard_blocks >= 3
  AND 通过白名单、拓扑、地址族、保护作用域、容量和速率安全门
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
2. IPC 使用请求响应、单向事件还是二者组合？
3. 首选后端是 nftables，还是根据发行版自动选择？
4. 支持的最低 Linux kernel、nftables 和 ipset 版本是什么？
5. scanner 和 CC 的初始晋升阈值如何通过 observe 数据确定？
6. 是否允许按重复攻击阶梯式延长 TTL？
7. Docker 首期是否只支持宿主机 Helper？
8. IPv6 单地址封禁何时默认开启？
9. 是否永远禁止自动 IPv6 `/64` 聚合，还是保留实验开关？
10. 与 firewalld、ufw 和 Docker 规则的支持矩阵如何定义？
11. 是否需要未来对接 CDN/云防火墙 API，若需要应作为独立 backend 还是独立产品层？

---

## 总结

内核层 IP 封禁适合作为 VeryNginx 的二级执行层：

```text
应用层检测和积累证据
  -> 独立晋升策略
  -> 特权 Helper
  -> nftables/ipset 临时集合
  -> 后续数据包在 Nginx 前 DROP
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
