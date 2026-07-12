# Kernel IP Blocking 实施计划

> **版本**: Draft v1.0
>
> **日期**: 2026-07-12
>
> **状态**: 待执行
>
> **前置条件**: `docs/KERNEL_IP_BLOCKING_DESIGN.md` v0.5

---

## 目录

1. [概述](#1-概述)
2. [Phase 0: 基础设施改造](#2-phase-0-基础设施改造)
3. [Phase 1: 证据采集 (Observe Only)](#3-phase-1-证据采集-observe-only)
4. [Phase 2: Reconciliation 只读阶段](#4-phase-2-reconciliation-只读阶段)
5. [Phase 3: 影子同步 (Shadow Reconcile)](#5-phase-3-影子同步-shadow-reconcile)
6. [Phase 4: 真实执行 (Canary 写内核)](#6-phase-4-真实执行-canary-写内核)
7. [Phase 5: 安装集成](#7-phase-5-安装集成)
8. [Phase 6: Dashboard 与 API](#8-phase-6-dashboard-与-api)

---

## 1. 概述

`KERNEL_IP_BLOCKING_DESIGN.md` 描述了完整的技术方案。本计划将其拆解为可独立交付、可回滚的阶段，每个阶段有独立的退出条件和验证手段。

核心风险：内核层的错误封禁可能阻断正常流量。因此设计"信任缓慢"——前四个阶段完全不写内核，只在 shared dict 中采集证据和验证逻辑，直到有充分数据支撑才真正写 nftables。

### 阶段总览

| Phase | 名称 | 写内核 | 可 exit | 退出条件 |
|-------|------|--------|---------|----------|
| 0 | 基础设施改造 | 否 | 是 | schema + migration + counter v2 通过测试 |
| 1 | 证据采集 | 否 | 是 | observe 指标稳定，候选数据合理 |
| 2 | Reconciliation 只读 | 否 | 是 | 差异可解释，reconciliation 逻辑正确 |
| 3 | 影子同步 | 否/隔离 | 是 | shadow 模式验证 reconciliation 无漂移 |
| 4 | 真实执行 | 是 | 是 | 误封率和性能指标达标 |
| 5 | 安装集成 | 是 | 是 | 支持矩阵内发行版全部通过 |
| 6 | Dashboard/API | 是 | 是 | 运维手册完备 |

### 目录结构规划

```
verynginx/
├── core/
│   ├── kernel_blocking/              ← 新增
│   │   ├── init.lua                  ← 配置、状态转换、生命周期
│   │   ├── promotion.lua             ← Promotion Policy
│   │   ├── evidence.lua              ← 证据采集 API (scanner/CC)
│   │   ├── executor_contract.lua     ← Nft Executor 接口定义
│   │   ├── desired_state.lua         ← 期望状态管理
│   │   ├── dispatch.lua              ← IPC 派发队列
│   │   ├── reconciliation.lua        ← Reconciliation 逻辑
│   │   ├── whitelist_generation.lua  ← 白名单 generation 管理
│   │   ├── promotion_token_bucket.lua ← 自动晋升令牌桶
│   │   ├── ip_encoding.lua           ← IP 规范化工具
│   │   └── readiness.lua             ← Frequency v2 + CC readiness
│   ├── frequency/
│   │   ├── init.lua                  ← Frequency Rule ID 管理 + migration
│   │   ├── limiter.lua               ← v2 namespace + evidence recording
│   │   └── rule_id_migration.lua     ← ID migration 工具
│   └── config_schema.lua             ← 重构后的递归 schema walker
├── helper/                            ← 新增 (独立仓库或子目录)
│   ├── firewall-helper.(ext)         ← 特权 Helper 实现
│   └── protocol_v1.(ext)             ← IPC Protocol v1 实现
test/v2/spec/
├── kernel_blocking_init_spec.lua
├── kernel_blocking_promotion_spec.lua
├── kernel_blocking_evidence_spec.lua
├── kernel_blocking_token_bucket_spec.lua
├── kernel_blocking_whitelist_gen_spec.lua
├── kernel_blocking_state_machine_spec.lua
├── kernel_blocking_readiness_spec.lua
├── frequency_rule_id_migration_spec.lua
├── frequency_v2_namespace_spec.lua
└── config_recursive_schema_spec.lua
```

---

## 2. Phase 0: 基础设施改造

**目标**: 改造现有系统的三个阻塞点，使其满足 Design 要求。
**预估工作量**: 2-3 个 PR
**写内核**: 否

---

### 2.1 递归配置 Schema Walker

**动机**: 当前 `normalize_defaults()` 仅深拷贝顶层，无法类型校验、不能拒绝未知字段，不能安全承载 `kernel_ip_blocking` 整棵子树。

**实现内容:**

1. **新建 `core/config_schema.lua`**，导出 `recursive_normalize(schema_node, raw_value, opts)`:
   - `schema_node` 定义: `{ type = "integer"|"boolean"|"string"|"array"|"object", default = ..., required = bool, allowed_values = {...}, min/max (integer), regex (string), children (object) }`
   - 对 "object" 类型逐字段递归: 对 schema 中定义的字段校验类型并补全默认; 对 `raw_value` 中的未知字段，按节点 `unknown_fields_policy = "reject"|"preserve"` 决定
   - 对 "array" 类型校验 dense array，可选 `item_schema`
   - 对 "string" 可选 `enum` 约束
   - 对 "integer" 可选 `min/max`
   - `opts` 包含 `path` (用于错误报告)、`phase = "load"|"save"|"hot_reload"`

2. **Save Pipeline (写前校验)**:
   ```
   copy raw candidate
     -> recursive_normalize(candidate, {phase = "save", unknown_fields_policy = "reject"})
     -> 跨字段交叉验证 (cross_validate)
     -> 编译不可变运行时快照
     -> backup + 原子 rename 持久化
     -> 原子替换运行时快照 (config_data)
     -> 执行 post-activation hooks
   ```
   校验/编译全部成功前不得触碰磁盘。成功后 post-activation 失败不回滚配置，状态进入 degraded。

3. **Load Pipeline (启动加载)**:
   ```
   read persisted bytes
     -> JSON parse
     -> recursive_normalize(parsed, {phase = "load", unknown_fields_policy = "reject"})
     -> cross_validate
     -> compile immutable snapshot
     -> activate (不写盘、不修复、不迁移)
   ```
   失败时保留文件不动，激活安全的内存默认快照 (kernel blocking 强制 disabled)。

4. **Hot Reload Pipeline**:
   与 startup 相同的只读 parse/normalize/validate/compile 流程。失败时保留 last-known-good 快照 + hash。失败不得发布新的 config hash、whitelist generation、activation generation、scope digest。

5. **跨字段校验 (`cross_validate`)**:
   - `reconcile_interval >= batch_interval`
   - `cc.max_ttl >= cc.ttl`
   - `scanner.max_ttl >= ip_reputation.flag_duration`
   - `cc.ttl >= 60 && cc.ttl <= 3600`
   - enforce 时 `topology == "direct"` && `protected_addresses` 非空 && `protected_ports` 非空
   - enforce 时至少启用一个与保护地址一致的地址族

6. **运行时快照不可变性**:
   规范化后的 `config_data` 生成 deep-copy-on-write 语义。模块只读引用，必须通过 save → normalize → 替换 的流程修改。

**影响文件**:
- 新建: `verynginx/core/config_schema.lua`
- 重构: `verynginx/core/config.lua` (保留对外 API，内部委托 recursive_normalize)
- 修改: `verynginx/configs/config.default.json` (新增 `kernel_ip_blocking` 默认块)

**测试**:
- `test/v2/spec/config_recursive_schema_spec.lua`:
  - 递归归一化: 叶子字段缺失补默认、类型错误报错、未知字段拒绝、嵌套对象部分补全
  - 跨字段校验: `max_ttl < ttl` 拒绝、enforce 时 topology 不匹配拒绝
  - save pipeline: 验证通过才写盘，验证失败不动盘
  - load pipeline: 损坏 JSON 不写盘，激活默认快照
  - hot reload: 失败保留 last-known-good，hash 不发布

---

### 2.2 Frequency Rule ID 系统 + Migration

**动机**: 当前 frequency rules 没有稳定唯一 ID，CC promotion 的 `cc.rule_ids` 无法引用。

**实现内容:**

1. **新建 `verynginx/core/frequency/rule_id_migration.lua`**:

   **ID 验证**:
   - 合法 ID: JSON string、UTF-8 字节长度 `1..128`、完全匹配 `[A-Za-z0-9._-]+`
   - 保留第一次出现的合法非空唯一 ID
   - `missing` = absent/null/empty string
   - `invalid` = non-string/illegal/oversized
   - `duplicate` = 重复合法 ID 的第二项及后续

   **m1 ID 生成**:
   ```
   canonical_rule = RFC 8785 JSON Canonicalization Scheme(rule with "id" removed)
   old_id_marker =
     "missing"                              # absent/null/empty string
     "present:" + 原始合法字符串 ID           # duplicate valid ID
     "invalid:" + base64url_no_padding(
         SHA-256(RFC 8785 canonical bytes of original id value)
     )                                       # non-string/illegal/oversized

   duplicate_ordinal = 同一合法非空原 ID 的 1-based 出现序号; missing/invalid 使用 0

   preimage =
     "verynginx-frequency-id-migration\n" +
     "m1\n" +
     decimal(original_array_index_1_based) + "\n" +
     old_id_marker + "\n" +
     decimal(duplicate_ordinal) + "\n" +
     decimal(collision_attempt) + "\n" +
     canonical_rule

   digest = SHA-256(UTF-8 bytes of preimage)
   new_id = "freq_m1_" + base64url_no_padding(full 32-byte digest)
   ```

   输出固定 51 个 ASCII 字符。

   **Migration 执行**:
   - 在现有 config save lock 下执行
   - 读取磁盘 pre-cutover 配置，检查全部 frequency rules (含禁用规则)
   - 生成新 ID 集合并验证引用完整性
   - `cc.rule_ids` 有歧义引用时中止
   - 使用 backup + 原子 rename 持久化
   - 重读落盘结果验证全部 ID 非空、唯一、稳定
   - 写入 bounded 升级审计

   **幂等与失败**:
   - 再次执行不改变配置
   - rename 前失败保持原配置不变
   - 无法唯一映射时中止 cutover

2. **新建 `verynginx/core/frequency/init.lua`**:
   - `get_rule_ids()`: 返回所有 frequency rule 的稳定 ID 数组
   - `resolve_rule_id(rule_id)`: 验证 + 返回完整 rule
   - `get_migration_status()`: 返回 migration 状态 (未迁移 / 已迁移 + 映射摘要)

3. **修改 `verynginx/plugin/frequency_limit/init.lua`**:
   - 初始化时给不带 ID 的规则生成临时 ID (在 migration 完成前使用; migration 完成后冻结 ID)
   - 新增 `evidence_mode` flag: 当 migration 完成后启用 v2 行为

**影响文件**:
- 新建: `verynginx/core/frequency/rule_id_migration.lua`
- 新建: `verynginx/core/frequency/init.lua`
- 修改: `verynginx/plugin/frequency_limit/init.lua`

**测试**:
- `test/v2/spec/frequency_rule_id_migration_spec.lua`:
  - RFC 8785 canonicalization 测试向量 (黄金文件对比)
  - missing/empty/null ID → `missing` marker
  - 非字符串/超长/非法字符 → `invalid` marker
  - 重复 ID → duplicate marker 且每次生成不同
  - 禁用规则同样需要 ID
  - collision attempt 递增
  - 相同输入逐字节确定性输出
  - 歧义引用 (`cc.rule_ids` 引用重复 ID → 中止)
  - 唯一非法引用原子更新
  - rename 前中断、断电容错
  - 回读验证

---

### 2.3 Frequency Counter Key v2 Namespace

**动机**: 现有限频 key 没有 rule ID，无法区分不同规则使用相同 dimension 的情况。

**实现内容:**

1. **修改 `verynginx/plugin/frequency_limit/limiter.lua` 的 `build_key()`**:
   - 新契约: 只返回维度部分 (不返回带 `fl:` 前缀的完整 key)
   - rule_id 和所有可变 dimension 使用长度前缀编码、URL-safe 编码或固定摘要
   - IPv4/IPv6 必须先规范化

2. **修改 `verynginx/plugin/frequency_limit/init.lua`**:
   - 当前计数 key: `fl:v2:count:<encoded_rule_id>:<encoded_dimension_key>`
   - CC violation evidence key: `fl:v2:kernel:violation:<encoded_rule_id>:<canonical_ip>:<evidence_slot>`
   - 保留现有 "计数 key 首次创建后按 `rule.window` TTL 过期" 语义
   - evidence_slot = `floor(ngx.time() / rule.window)`
   - 当 `current == limit + 1` 时用 `shared:add()` 写入当前 slot marker
   - evidence TTL >= `rule.window × (cc.min_violation_windows + 1)`

3. **IP 规范化/编码工具**:
   - `normalize_ipv4(string)`: 去除 leading zeros
   - `normalize_ipv6(string)`: 展开 + lowercase + compress
   - `encode_rule_id(string)`: 长度前缀编码
   - 新建 `verynginx/core/kernel_blocking/ip_encoding.lua` 存放

4. **冷切换契约**:
   - 共享状态记录 `counter_namespace = "v2"` 和统一 `cutover_epoch`
   - 所有 active 计量窗口重置 (最长一个 `rule.window`)
   - 不对旧 `fl:*` key 双读、双写或转换
   - 回滚到旧代码会再次重置窗口

**影响文件**:
- 修改: `verynginx/plugin/frequency_limit/limiter.lua`
- 修改: `verynginx/plugin/frequency_limit/init.lua`
- 新建: `verynginx/core/kernel_blocking/ip_encoding.lua`

**测试**:
- `test/v2/spec/frequency_v2_namespace_spec.lua`:
  - v2 key 唯一无碰撞 (不同 rule_id + 相同 dimension)
  - IP 规范化: leading zeros、IPv6 展开/压缩
  - `build_key()` 纯 dimension 不带回前缀
  - 超限 marker 只在 `current == limit + 1` 写入
  - evidence TTL >= window × (min_violation_windows + 1)
  - 两个固定 TTL 计数生命周期在边界情况下落入同一 evidence slot → 保守合并
  - observe 模式不写 v2 evidence

---

### 2.4 暴露 IP 声誉内部接口

**动机**: Promotion Policy 需要读取 `slot_size` 和 `window_size` 计算 evidence 窗口，但当前是 private。

**实现内容:**

1. **修改 `verynginx/core/ip_reputation.lua`**:
   - 导出 `slot_size()` → 返回当前 slot 大小 (秒)
   - 导出 `window_size()` → 返回当前窗口大小 (秒)
   - 导出 `flag_duration()` → 返回当前 flag duration
   - 修复 `add_whitelist()` bug (`cfg` 引用错误、`config.save()` 传错参数)

2. **新建 `verynginx/core/kernel_blocking/evidence.lua`**:
   - `record_waf_block_evidence(ip)`: scanner 用 — `shared:incr("ip_rep:kernel:waf_block:" .. ip .. ":" .. slot, 1, 0, window_size())`
   - `record_cc_violation_evidence(rule_id, ip, window)`: CC 用 — `shared:add("fl:v2:kernel:violation:" .. rule_id .. ":" .. ip .. ":" .. slot, true, ttl)`
   - 两者遵循有界原子操作，不执行 IPC/JSON 通信/磁盘 I/O

**影响文件**:
- 修改: `verynginx/core/ip_reputation.lua` (暴露接口 + 修 bug)
- 新建: `verynginx/core/kernel_blocking/evidence.lua`

---

### 2.5 Phase 0 退出验证

- [ ] 全部 Phase 0 单元测试通过
- [ ] 现有测试套件无回归
- [ ] Frequency Rule ID Migration 在 sample config 上 dry-run 幂等
- [ ] v2 counter namespace 冷切换后 limit 计数正确 (不丢、不翻倍)
- [ ] Schema walker 拒绝未知字段但接受旧配置 (backward compatible)

---

## 3. Phase 1: 证据采集 (Observe Only)

**目标**: 在请求路径只记录证据，不生成可安装的期望状态。Promotion Policy 在后台评估 evidence 并生成 (would_promote, would_rate_limit, rejection_reason) 指标。
**预估工作量**: 2-3 个 PR
**写内核**: 否

---

### 3.1 新增配置块

在 `config.default.json` 添加 `kernel_ip_blocking` 默认块:

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
    "max_entries": { "scanner": 100000, "cc": 50000, "manual": 10000 },
    "scanner": { "enabled": true, "require_flagged": true, "min_hard_blocks": 3, "max_ttl": 86400 },
    "cc": { "enabled": true, "enforce_ready": false, "rule_ids": [], "ttl": 300, "max_ttl": 1800, "min_violation_windows": 3, "require_challenge_fail": true },
    "ipv4": { "enabled": true },
    "ipv6": { "enabled": false, "prefix_aggregation": false },
    "promotion_rate_limit": { "limit": 1000, "interval": 60, "burst": 1000 }
  }
}
```

由 Phase 0 的 schema walker 保证安全归一化。

---

### 3.2 请求路径证据写入

**不改变现有 plugin 行为**，仅在已有信号点旁追加同步的、有界的 shared dict 写入。

1. **`plugin/filter/init.lua`**:
   - 在 `record_signal(ip, "waf_block")` 后，调用 `evidence.record_waf_block_evidence(ip)`
   - 证据 key: `ip_rep:kernel:waf_block:<ip>:<slot>`，TTL = `window_size()`

2. **`plugin/frequency_limit/init.lua`**:
   - 在 `current == limit + 1` 时调用 `evidence.record_cc_violation_evidence(rule.id, ip, rule.window)`
   - 证据 key: `fl:v2:kernel:violation:<rule_id>:<ip>:<evidence_slot>`

**通用约束**:
- 只有 `kernel_ip_blocking.enabled == true` 时执行写入
- observe 模式也写入证据 (observe 只是不自装内核)
- 写入失败静默降级 (log warning，不影响请求)

---

### 3.3 Promotion Policy (Observe 模式)

**新建 `verynginx/core/kernel_blocking/promotion.lua`**:

**worker 0 batch callback** (`process_candidates(now)`):
1. 消费有界候选索引 (基于 existing WAF 命中 + frequency violation marker)
2. 逐候选分两步评估:
   - **loose 门槛**: `window` 内 `min_hard_blocks >= 1` (scanner) / 首次超限 (CC)
   - **strict 门槛**: 已 `flagged` AND `window` 内 `min_hard_blocks >= 3` (scanner) / 连续 `min_violation_windows` 超限 (CC)
3. observe 模式下只记录 `would_promote` (strict 通过) / `would_rate_limit` (被安全门拒绝) / `rejection_reason`

**虚拟令牌桶** (observe 专用，不消耗 enforce 桶 token):
- key: `kb:promotion_bucket:v1:observe:state` / `:lock`
- 独立于 enforce 桶
- 计算 `would_rate_limit` 用于 dashboard

**安全门评估** (按 Design §6.1):
1. 功能 enabled + mode != observe-only-for-this-policy
2. IP 格式有效，地址族受支持
3. IP 不属于 whitelist / auto-whitelist / trusted infrastructure
4. IP 非回环/链路本地/组播/未指定/本机管理地址
5. 网络拓扑允许内核匹配 (non-CDN / TLS offloaded locally)

**scanner 候选评估**:
```
strict 通过 =
  ip_reputation.is_flagged(ip)
  AND sum(slot counts) >= scanner.min_hard_blocks
  AND current slot 在 window_size 内
  AND NOT 任何安全门拒绝
```

**CC 候选评估**:
```
strict 通过 =
  至少 min_violation_windows 个 violation marker 未过期
  AND (NOT cc.require_challenge_fail OR 该 IP Evidence 期内有 challenge_fail)
  AND NOT 任何安全门拒绝
```

---

### 3.4 Reconciliation (Observe 只读)

**新建 `verynginx/core/kernel_blocking/reconciliation.lua` (observe 阶段只读模式):**

worker 0 reconcile callback:
1. 读取期望状态 (空，因为 observe 不创建)
2. 如果有孤立的已安装条目 (人为 / 以前测试的残留)，仅报告不删除
3. 计算 `drift_metrics`: 已安装但不期望的条目、期望但未安装的条目

---

### 3.5 指标与审计

**Prometheus 指标** (Phase 1 只有 observe 级别):

```text
verynginx_kernel_block_candidates_total{policy,level,result}
verynginx_kernel_block_promotions_total{list,result}           # Phase 1 恒为 0
verynginx_kernel_block_operations_total{operation,result}       # Phase 1 恒为 0
verynginx_kernel_block_sync_latency_seconds                     # Phase 1 恒为 0
verynginx_kernel_block_reconcile_drift                          # Phase 1 报告孤立条目
verynginx_kernel_block_queue_dropped_total                     # Phase 1 恒为 0
verynginx_kernel_block_promotion_tokens                        # Phase 1 虚拟桶余额
verynginx_kernel_block_allow_generation_lag                    # Phase 1 为 0
```

`level` 仅允许 `loose|strict`，仅 `strict` 等同 enforce 模式实际会安装的候选。

**审计字段** (Phase 1 记录 observe 决定):
- operator = `"system"`
- action = `"would_promote"` / `"would_rate_limit"` / `"rejected"`
- reason + evidence summary

---

### 3.6 状态机 (Phase 1 范围)

Phase 1 仅产生以下状态:

```text
observed → candidate (loose/strict)
  ├─ 安全门拒绝 → rejected (observe 仅记录 rejection_reason)
  └─ 不满足 strict → 保持 candidate
```

无 `promoted` / `installed` 等后续状态 (observe 模式不创建可安装的期望状态)。

Phase 1 状态记录在 shared dict 的候选索引中 (有界)，`candidate` 条目 7 天后自动过期 (同 waf_recommender 策略)。

---

### 3.7 白名单 Generation 机制

**新建 `verynginx/core/kernel_blocking/whitelist_generation.lua`**:

1. **生成 epoch 和 sequence**:
   - epoch: 每次 Nginx master 启动生成不可预测 boot ID
   - sequence: 该 epoch 内从 1 开始原子递增的整数
   - shared storage: `ip_rep:whitelist_epoch` (string) + `ip_rep:whitelist_sequence` (counter)

2. **修改 `core/ip_reputation.lua` 的 `is_whitelisted()`**:
   - 查缓存前读取当前 `{epoch, sequence}`
   - 正、负缓存都只写入 generation-qualified key: `ip_rep:wl_cache:<epoch>:<sequence>:<canonical_ip>`
   - 不再读写无 generation 的 `ip_rep:wl_cache:<ip>`

3. **修改白名单变更流程**:
   - 验证并规范化完整候选白名单
   - `config.save()` 原子持久化并激活
   - 成功后原子递增 sequence
   - 静态白名单变更后通过一次性 `ngx.timer.at(0, ...)` 异步发送最新完整 snapshot 到 Helper (Phase 1 可只记录 "pending_refresh"，不发 IPC)

4. **旧 generation 缓存回收**: 依赖短 TTL 自然过期，不 `get_keys()` 扫描

---

### 3.8 Phase 1 退出验证

- [ ] observe 模式候选 IP 中不包含管理员 / 搜索引擎 / 监控 / 共享出口
- [ ] 每天产生严格数量的 scanner/CC 候选 (数据观察)
- [ ] 候选持续时间和重复率可分析
- [ ] observe 模式严格不写内核 (executor / IPC / nft 未 mock 调用)
- [ ] 全部 Phase 1 单元测试通过
- [ ] 现有测试套件无回归

---

## 4. Phase 2: Reconciliation 只读阶段

**目标**: 实现完整的 Reconciliation 逻辑，但仅在 "dry-run" 模式下运行 (不发送 mutating IPC 请求)。验证期望状态与实际状态的差异计算正确。
**预估工作量**: 1-2 个 PR
**写内核**: 否 (dry-run 模式，仅日志记录 "would_install" / "would_delete")

---

### 4.1 Nft Executor 合约 (Mock 实现)

**新建 `verynginx/core/kernel_blocking/executor_contract.lua`** (与 Design §9.2 一致):

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

Phase 2 提供一个 `mock_executor` 实现: 所有写在 shared dict 中模拟，所有读从 shared dict 中读取。这允许端到端测试 reconciliation 逻辑而不依赖特权 Helper。

真实 nftables executor 在 Phase 4 之前不被调用。

---

### 4.2 期望状态管理

**新建 `verynginx/core/kernel_blocking/desired_state.lua`** (但在 Phase 2 还不创建真实期望状态，只记录 dry-run 结果):

Phase 2 产生 dry-run 的期望状态记录:
```json
{
  "ip": "203.0.113.10",
  "family": "ipv4",
  "list": "scanner_drop",
  "dry_run_state": "promoted",
  "reason": "repeated_hard_block",
  "evidence": { "score": 42, "hard_block_hits": 5, "distinct_categories": 2 },
  "policy_version": 1,
  "created_at": 1783728000,
  "simulated_expires_at": 1783731600,
  "source": "automatic"
}
```

`dry_run_state` 仅用于日志/display，不发给 Helper。

---

### 4.3 Reconciliation 逻辑

worker 0 reconcile callback (Phase 2 只读 dry-run):

1. 读取 Helper health (mock → 始终 ok)
2. 分页读取实际内核集合状态 (mock → 从 shared dict)
3. 计算期望 vs 实际的差异:
   - `to_add`: 期望但实际不存在 → 日志 "would_install"
   - `to_update`: 期望已存在但 TTL 不同 → 日志 "would_update"
   - `to_remove`: 实际存在但不再期望 → 日志 "would_remove"
4. 记录 drift 指标

**不执行 delete** 在 observe 模式 + dry-run 模式下 (只报告)。

---

### 4.4 Phase 2 退出验证

- [ ] dry-run reconciliation 日志差异计算正确
- [ ] "would_install" 列表与 Promotion Policy 的 `would_promote` 一致
- [ ] mock executor 接口完整 (8 个方法)
- [ ] 全部 Phase 2 单元测试通过
- [ ] 现有测试套件无回归

---

## 5. Phase 3: 影子同步 (Shadow Reconcile)

**目标**: 在隔离的网络命名空间中运行完整的 Kernel Blocking 链路 (包括真实的 nftables 写入)，验证端到端的正确性。
**预估工作量**: 2-3 个 PR
**写内核**: 仅在隔离 namespace 中 (canary 流量子集)

---

### 5.1 完整状态机

Phase 3 激活 Design §5.3 描述的全部状态:

```text
observed → candidate → rejected
                    → rate_limited → 保持 candidate
                    → promoted → dispatch_pending → degraded → reconcile
                                                → installed
                                                      ├─ TTL 到 → expired
                                                      ├─ 管理员解除 → cleared
                                                      ├─ 白名单覆盖 → cleared
                                                      └─ 同步失败 → degraded → reconcile
```

加上 Phase 3 需要的 `scope_validation_pending` 转换 (断线 / Helper 重启后)。

---

### 5.2 Helper 启动

**实现 IPC Protocol v1 客户端** (在 Lua 层):

1. 连接 Unix Socket (`/run/verynginx/firewall-helper.sock`)
2. Framing: 4 字节无符号大端长度 + UTF-8 JSON
3. 操作: `probe`, `health`, `ensure_base`, `add`, `delete`, `list`, `replace_allow_snapshot`, `reconcile`, `flush_owned`
4. 身份: `SO_PEERCRED` 或目标平台等价机制
5. 超时: connect 100ms, read/write 2s, idle 5s

**Helper 本身** 的初期实现可以是用 Python/Rust 写的独立进程，接受 LPS 编码的 JSON 请求，调用 `/usr/sbin/nft -f -` 并返回结构化响应。放在 `helper/` 目录下。

---

### 5.3 Shadow 模式

Phase 3 的 "canonical executor" 在隔离容器中运行:

- 使用单独的 nftables table 名 (如 `table inet verynginx_shadow`)
- 不影响生产流量
- 管理 API 仍然 receipt request 但标记为 shadow
- Dashboard 明确显示 "影子模式" / "不直接影响流量"

---

### 5.4 白名单 Generation → Helper Snapshot

Phase 3 连接真实的 `replace_allow_snapshot`:

- 白名单变更 → IPC → Helper 在同一 transaction 更新 allow + 移除被覆盖的 DROP
- 失败的 transaction 不更新 Helper 已安装 generation
- 控制面 generation 与 Helper installed generation 不一致时状态为 `allow_refresh_pending`

---

### 5.5 Phase 3 退出验证

- [ ] shadow nftables table 中 DROP 集合实际匹配预期的 IP
- [ ] allow 使用 RETURN，不影响生产路由
- [ ] allow 更新后立即生效 (不等待 reconciliation 周期)
- [ ] Helper 重启后 scope_validation_pending 和重建流程正确
- [ ] disabled 时队列丢弃、已安装条目保持、不在重启用后恢复
- [ ] 全部 Phase 3 单元测试通过
- [ ] 现有测试套件无回归

---

## 6. Phase 4: 真实执行 (Canary 写内核)

**目标**: Production 流量 canary — 小比率晋升、短 TTL，逐步放大。
**预估工作量**: 2-3 个 PR
**写内核**: 是 (canary)

---

### 6.1 启用真实 Executor

将 mock executor 替换为真实 nftables executor:

- 使用 `/usr/sbin/nft -f -` 批处理
- 用 `nft -j list ...` 接口读取状态
- subproc 错误映射为结构化错误码

---

### 6.2 令牌桶生效

Phase 4 开始 enforce 桶消耗真实 token:
- 首次晋升: -1 token
- cc_drop 升级为 scanner_drop: -1 token
- 自动续期 (延长 expires_at): -1 token
- 无 token 时保持 candidate，结果 `rate_limited`

---

### 6.3 启动 Canary 短 TTL

默认:
- scanner canary TTL = 60 秒
- CC canary TTL = 30 秒

---

### 6.4 Emergency Break-Glass

Phase 4 必须包含独立的紧急操作:

| 动作 | 说明 |
|------|------|
| `pause promotion` | 停止新增，不动现有 |
| `flush auto` | 清理 scanner/CC 自动集合，保留 manual |
| `flush all owned` | 清理全部 VeryNginx 自有集合 |
| `detach chain` | 移除 jump/chain |
| `disable config` | 停止晋升并使下次启动保持关闭 |

所有动作相互独立，`disable` 不隐式清理。

---

### 6.5 Phase 4 退出验证

- [ ] canary 流量的被封 IP 不再到达 Nginx 请求处理链
- [ ] 自动封禁 TTL 正确执行自动解除
- [ ] 紧急解除手动 IP 封禁在 30 秒内生效
- [ ] Helper 不可用时 fail-open (现有 Lua WAF 继续工作)
- [ ] 误封率 < 0.01% (基于 canary 数据分析)
- [ ] 全部 Phase 4 单元测试通过
- [ ] 现有测试套件无回归

---

## 7. Phase 5: 安装集成

**目标**: 配套 LNMP 脚本集成，支持矩阵内发行版全部通过。
**预估工作量**: 1-2 个 PR
**写内核**: 是

---

### 7.1 LNMP 脚本集成

`install-lnmp.sh` 新增:

- 安装 nftables 用户态工具 (发行版包管理器)
- capability probe: `inet` family、interval set、timeout element、原子 transaction
- 部署 Helper systemd service
- 创建 Unix Socket 目录、用户组和权限
- 检测 UFW / Docker / `iptables-nft` / 已有 `table inet verynginx`

能力检查成功不自动进入 enforce。仍保持 disabled/observe。

---

### 7.2 Docker 支持

- Helper 运行在宿主机
- VeryNginx 容器通过受限挂载的 Unix Socket 提交事件
- 不给主容器 `--privileged`
- 不给主容器 `NET_ADMIN`
- 默认 Docker 模式只允许 observe

---

### 7.3 发行版兼容性清单

| 组件 | Debian 12 | Ubuntu 24.04 | 更低版本 |
|------|-----------|--------------|----------|
| nftables | ✓ | ✗ | ✗ |
| kernel 6.x | ✓ | ✓ | 可能 |
| libnftables | 可选 | 可选 | - |

---

### 7.4 Phase 5 退出验证

- [ ] Debian 12 / Ubuntu 24.04 安装、启动、probe 全部成功
- [ ] UFW 共存不冲突
- [ ] Docker 模式下 observe 工作正常
- [ ] 能力检查失败时 fail-open + 清晰告警
- [ ] 全部 Phase 5 单元测试通过
- [ ] 现有测试套件无回归

---

## 8. Phase 6: Dashboard 与 API

**目标**: 运维管理界面和 API，体验完备。
**预估工作量**: 2-3 个 PR
**写内核**: 是

---

### 8.1 API 路径

继承现有 controller 注册体系:

| 方法 | 路径 | 用途 |
|------|------|------|
| GET | `/kernel-blocking/status` | Helper、nftables、模式和集合统计 |
| GET | `/kernel-blocking/entries` | 分页查询期望和实际条目 |
| GET | `/kernel-blocking/candidates` | observe 模式候选 |
| POST | `/kernel-blocking/promote` | 人工封禁 |
| POST | `/kernel-blocking/clear` | 人工解除 |
| POST | `/kernel-blocking/reconcile` | 手动触发同步 |
| POST | `/kernel-blocking/pause` | 停止新增晋升 |
| POST | `/kernel-blocking/flush-auto` | 清理自动集合 |

所有 mutating API 必须继承现有中间件 (Auth / CSRF / Rate Limit / Idempotency-Key / Audit / Response Size Limit)。

---

### 8.2 Status 响应结构

```json
{
  "configured": { "enabled": true, "mode": "enforce" },
  "effective": {
    "global_mode": "enforce",
    "global_install_reachable": true,
    "scanner": { "mode": "enforce", "install_reachable": true, "reason_codes": [] },
    "cc": { "mode": "observe", "install_reachable": false, "reason_codes": ["cc_not_enforce_ready"] }
  },
  "health": { "state": "ok", "helper_instance_id": "..." },
  "migration": { "status": "completed", "cutover_epoch": 1783728000 },
  "whitelist_generation": { "control_plane": {"epoch": "...", "sequence": 5}, "helper_installed": {"epoch": "...", "sequence": 5} },
  "promotion_bucket": { "tokens_available": 850, "rate_limited_recent": 12 },
  "counters": { "scanner_candidates": 45, "cc_candidates": 12, "installed_scanner": 23, "installed_cc": 5, "installed_manual": 2 }
}
```

包含 Design §11.5 全部 effective-state 矩阵。

---

### 8.3 Dashboard 区域

新增 "Kernel Blocking" tab 区域 包含:

- configured global toggle/mode 和 effective modes (global / scanner / CC)
- 独立的 health badge (`ok` / `degraded` / `unavailable`)
- global / scanner / CC 分开的 reachability badge + fixed reason + 对应处理建议
- 集合统计 (scanner/cc/manual 条目数)
- disabled-but-active-entries 警告 + flush-auto 入口
- 最近晋升和解除记录 (时间线)
- 候选 IP、证据、模拟命中数量
- 期望状态 vs 实际状态差异
- Frequency ID migration 状态 + v2 冷切换 + CC rule status
- 白名单 generation 控制面 / Helper 差异
- 自动晋升桶余额 + 近期 `rate_limited` 拒绝
- 单 IP 详情抽屉
- 操作按钮: 暂停新增 / 解除单条 / 清理自动 / 触发 reconcile

`cc.enforce_ready` 在全局 observe 模式下也能查看和编辑。危险弹窗二次确认。不提供任意 nftables 规则编辑器。

---

### 8.4 Phase 6 退出验证

- [ ] Dashboard 覆盖 Design §12.2 全部要点
- [ ] API 通过全部现有中间件
- [ ] 人工封禁 / 解除在 5 秒内生效 (无需等待 reconciliation 周期)
- [ ] Phase 6 单元测试全部通过
- [ ] 现有测试套件无回归

---

## 附录 A: 文件清单

### 新建文件

```
verynginx/core/config_schema.lua                          (Phase 0)
verynginx/core/frequency/rule_id_migration.lua             (Phase 0)
verynginx/core/frequency/init.lua                          (Phase 0)
verynginx/core/kernel_blocking/init.lua                    (Phase 1)
verynginx/core/kernel_blocking/promotion.lua               (Phase 1)
verynginx/core/kernel_blocking/evidence.lua                (Phase 1)
verynginx/core/kernel_blocking/executor_contract.lua       (Phase 2)
verynginx/core/kernel_blocking/executor_mock.lua           (Phase 2)
verynginx/core/kernel_blocking/executor_nft.lua            (Phase 4)
verynginx/core/kernel_blocking/desired_state.lua           (Phase 2)
verynginx/core/kernel_blocking/dispatch.lua                (Phase 2)
verynginx/core/kernel_blocking/reconciliation.lua          (Phase 2)
verynginx/core/kernel_blocking/whitelist_generation.lua    (Phase 1)
verynginx/core/kernel_blocking/promotion_token_bucket.lua  (Phase 1)
verynginx/core/kernel_blocking/ip_encoding.lua             (Phase 0)
verynginx/core/kernel_blocking/readiness.lua               (Phase 0)
verynginx/helper/firewall_helper.*                         (Phase 3)
verynginx/helper/protocol_v1.*                             (Phase 3)
test/v2/spec/kernel_blocking_init_spec.lua                 (Phase 1)
test/v2/spec/kernel_blocking_promotion_spec.lua            (Phase 1)
test/v2/spec/kernel_blocking_evidence_spec.lua             (Phase 1)
test/v2/spec/kernel_blocking_token_bucket_spec.lua         (Phase 1)
test/v2/spec/kernel_blocking_whitelist_gen_spec.lua        (Phase 1)
test/v2/spec/kernel_blocking_state_machine_spec.lua        (Phase 3)
test/v2/spec/kernel_blocking_readiness_spec.lua            (Phase 0)
test/v2/spec/frequency_rule_id_migration_spec.lua          (Phase 0)
test/v2/spec/frequency_v2_namespace_spec.lua               (Phase 0)
test/v2/spec/config_recursive_schema_spec.lua              (Phase 0)
```

### 修改文件

```
verynginx/core/config.lua                    (Phase 0: 委托 recursive_normalize)
verynginx/core/ip_reputation.lua             (Phase 0: 暴露接口 + 修 bug)
verynginx/core/init.lua                      (Phase 1: 附加 worker 0 timers)
verynginx/plugin/filter/init.lua             (Phase 1: 追加 scanner evidence)
verynginx/plugin/frequency_limit/init.lua    (Phase 0+1: v2 namespace + CC evidence)
verynginx/plugin/frequency_limit/limiter.lua (Phase 0: build_key 契约)
verynginx/configs/config.default.json        (Phase 0: 新增 kernel_ip_blocking 默认)
verynginx/dashboard/index.html               (Phase 6: Kernel Blocking 区域)
```

---

## 附录 B: 关键依赖关系

```
Phase 0
  ├─ 2.1 Schema Walker         → 所有后续 phase 配置读写
  ├─ 2.2 Frequency Rule ID     → Phase 1 CC evidence → Phase 4 CC promotion
  ├─ 2.3 Counter Key v2        → Phase 1 CC evidence → Phase 4 CC promotion
  ├─ 2.4 IP Reputation 接口    → Phase 1 scanner evidence + 白名单 generation
  └─ 2.4 add_whitelist bugfix  → 与白名单相关所有 phase

Phase 1
  ├─ 3.1 配置块                → 由 Schema Walker 保证安全
  ├─ 3.2 请求路径证据           → 基于现有 hook 点 + 2.4 接口
  ├─ 3.3 Promotion Policy      → 需要 3.2 的证据
  ├─ 3.7 白名单 Generation     → 基于 2.4 暴露的接口
  └─ 所有 phase 1 产出          → phase 2 dry-run 输入

Phase 2
  ├─ 4.1 Executor Contract     → mock 实现
  ├─ 4.2 期望状态管理           → 由 phase 1 promotion 产生 (但 observe 模式不创建真实期望状态)
  └─ 4.3 Reconciliation dry-run → 验证差异计算逻辑

Phase 3
  ├─ 5.2 Helper                → IPC Protocol v1 完整实现
  ├─ 5.3 Shadow Executor       → 在隔离 namespace 运行真实链路
  └─ 5.4 白名单 Snapshot        → Phase 3 开始真实发送

Phase 4
  ├─ 6.1 真实 Executor         → 替换 mock
  ├─ 6.2 令牌桶生效             → 2.1 的 enforce bucket
  └─ 6.5 Break-Glass           → 紧急操作

Phase 5 和 Phase 6 依赖 Phase 4 链路稳定后生产可用。
```

---

## 附录 C: 风险控制

| 风险 | 缓解措施 |
|------|----------|
| Schema 重构引入 config 兼容性破坏 | Phase 0 优先跑 backward compatible 测试; unknown_fields_policy = "preserve" 对旧 top-level |
| ID Migration 数据丢失 | 原子 rename、失败保持原配置、幂等可重试 |
| v2 key 冷切换期间计数窗口重置 | 发布说明明确提示; 客户端最多获得一次新窗口 |
| Promotion 误封 | 前四阶段完全不写内核; canary 短 TTL; 紧急逃生通道 |
| Helper crash 导致封禁残留 | 自动 TTL 到期; 白名单 generation 高优先级刷新 |
| CDN 场景误封代理节点 | topology 配置门控; CDN 模式禁止 enforce |
| nftables 规则被外部修改 | Reconciliation + 周期性 drift 检测 |
| Helper IPC 超时阻塞请求 | 请求路径零阻塞; IPC 只在 worker 0 异步执行; dispatch 队列有界 |
