# P1 设计方案：请求统计按主机（host）维度 + 面板主机过滤

> 状态：**待审核**（未动手实现）
> 范围：只做「请求统计」的 host 维度，不做 metrics 标签、不做 per-host 规则隔离。

## 1. 目标

VeryNginx v2 现在是全局单实例：请求统计的 key 只有 `bucket + URI`，没有 host。多站点场景下，用户**看不到「这台主机今天多少请求、哪些 URI 最热、成功率多少」**。

本方案让请求统计按 `Host` 头区分，并在面板加一个「主机」下拉过滤，默认「全部主机」保持现有聚合行为不变。

**明确不做**（本次范围外）：
- metrics（`waf_rule_*`）加 host 标签 —— 基数爆炸风险，见 §8
- IP 声誉 per-host —— 那是 P2，独立开关
- WAF/频率规则 per-host 隔离 —— 全局默认是对的，不做

## 2. 现状数据流（`core/statistics.lua`）

```
summary 插件 log_request()
  └─ 采样 1/10，写 shdict「statistics」(20m)
       key:  1m:<uri>:count / :bytes / :time / :status_<code>
       index: index:1m → JSON 数组，存 uri 的 LRU（上限 max_uri_keys=10000）

定时 flush：1m→5m→1h→all（key 前缀随 bucket 变）
report(period)：读 index:<bucket>，输出 { [uri] = {count,bytes,time,status} }
get_top_paths(limit)：读 index:1m，返回 top-N uri
persist/restore：all bucket → configs/statistics.json
```

消费端 API：
- `GET /summary?type=short|medium|long` → `statistics.report(type)`（`api/controllers/config.lua:89`）
- `GET /stats/top-paths?limit=N` → `statistics.get_top_paths(N)`（`api/controllers/plugins.lua:105`）

前端（`vn-dashboard.js` / `index.html` 请求统计 tab）：
- `statsType` 下拉（全部/5分钟/临时）→ `loadStats()` → `statsData`（flat `{uri: {...}}`）
- `loadTopPaths()` → `topPaths`（数组 `{uri,count,bytes,time}`）

## 3. 核心设计决策

### 决策 A：host 维度只在统计层加，规则层不动
host 是「观察维度」，不是「配置维度」。规则仍然全局，统计按 host 分组展示。**这条是本方案与「per-host 规则隔离」的本质区别。**

### 决策 B：向后兼容 = 默认「全部主机」聚合
- `report`/`top-paths` 的 host 参数**缺省**时，输出与现在**完全一致**（跨 host 聚合的 flat 结构）。
- 前端默认不选 host = 现状。只有显式选了某个 host 才传 `host=`。

### 决策 C：host 的来源与归一化
- 来源：`ngx.var.host`（已去掉端口；空则回退 `ngx.var.server_name`，再空用 `_`）。
- 归一化：`小写` + `去尾部 "."`，避免 `Example.com` 与 `example.com.` 分叉成两个 host。
- IPv6 字面量（host 含 `[`/`:`）做 `ngx.crc32_short` 哈希后当 key，防止 `:` 污染 key 分隔（边缘 case，几乎不会触发）。

### 决策 D：存储 key 设计（复合 key，每 host 一个 uri 索引）

写入 `log_request`：
```
1m:<host>:<uri>:count / :bytes / :time / :status_<code>
index:1m:<host>   → JSON 数组，该 host 的 uri LRU
hosts:1m          → JSON 数组，全局活跃 host LRU（上限 max_hosts）
```

flush 改为「先遍历 hosts，再遍历每个 host 的 uri」，其余逻辑不变。

### 决策 E：uri 预算（需你拍板，见 §6 待决项）

`statistics` dict 只有 **20m**。现在总 key ≈ `10000 uri × ~5 = 5 万`，安全。若「每 host 独立 10000 uri」，50 host 就是 50 万 uri，会撑爆 dict。

因此必须引入**全局 uri 预算**。推荐方案：
- 保留 `max_uri_keys`（默认 10000）为**全局总预算**
- 新增 `max_hosts`（默认 **50**）
- 每 host 的 uri LRU 上限 = `max(ceil(max_uri_keys / max_hosts), 10)` → 单 host 时仍可吃满 10000，50 host 时每 host 200

## 4. API 契约

| 端点 | 改动 | 说明 |
|---|---|---|
| `GET /summary?type=X&host=Y` | 加可选 `host` | 缺省=聚合（现行为）；指定=只该 host。返回格式不变（flat） |
| `GET /stats/top-paths?limit=N&host=Y` | 加可选 `host` | 同上 |
| `GET /stats/hosts` | **新增** | 返回 `{ret:"success", data:["a.com","b.com"]}`，活跃 host 列表 |

`host` 参数做严格校验：`^[A-Za-z0-9._-]+$` 且 ≤253，非法返回 400（防注入/防 key 伪造）。

## 5. 前端改动

`index.html` 请求统计区域（line 515-583）：

```html
<!-- statsType 下拉旁边加一个 host 下拉 -->
<select v-model="statsHost" style="width:auto" @change="loadStats">
  <option value="">全部主机</option>
  <option v-for="h in statsHosts" :value="h">{{ h }}</option>
</select>
```

`vn-dashboard.js`：
- 新增 `statsHosts` ref + `loadHosts()`（调 `/stats/hosts`）
- `loadStats()` 改为 `GET /summary?type=${statsType}${statsHost ? '&host='+statsHost : ''}`
- `loadTopPaths()` 同理带 `host` 参数
- 进入 stats 页或登录后触发 `loadHosts()`（挂进已有的 `registerPoll` 或 `syncPolls` 生命周期，**不要**手写 setInterval，见 AGENTS.md §8.3b）

Top Paths 表也跟随 host 过滤（同一份 `statsHost`）。

## 6. 待你拍板的点

1. **`max_hosts` 默认值**：50（一台 LNMP 机器 <20 站点，够用且安全）。认可吗？
2. **uri 预算策略**：采用「全局总预算 10000 均分」还是「每 host 独立 10000、靠 max_hosts 兜底」？
   - 推荐前者（dict 安全），但代价是站点多时单站只保留 top 200 URI。
3. **Top Paths 是否也按 host 过滤**：我建议**跟随过滤**（和 URI 统计一致）。若你觉得 Top Paths 应恒为全局，可单独保留。

## 7. 迁移与兼容

- 统计是**易失数据**（非配置），升级时**直接重置**：
  - `statistics.json` 加顶层 `{"v":2, "data":{...}}` 版本号；`restore` 读到非 v2 或无版本号（旧 flat 格式）时**跳过并清空**，不迁移。
  - shdict 里的旧 `1m:<uri>:*` key 随自然 flush/重启消失，无需显式清理。
- 前端老版本访问新后端：`/summary` 不带 host 仍返回 flat，完全兼容。
- 新前端访问老后端：`/stats/hosts` 404 → 前端 catch 后隐藏 host 下拉（优雅降级）。

## 8. 为什么 metrics 本次不做（延后）

`metrics.lua` 的 per-rule 指标 `waf_rule_*` 已走 `metrics_labeled`（16m，TTL 3600s）。给它加 host 标签 = **规则数 × host 数**的基数爆炸，AGENTS.md §3.4 已明确警告。若要做，需要单独设计「top-N host 限流 + 标签裁剪」，和本方案解耦。故延后。

## 9. 改动文件清单

后端：
- `verynginx/core/statistics.lua` —— 核心（key 加 host、flush 遍历 hosts、report/get_top_paths 加 host 参数、新增 get_hosts、persist/restore 加版本号）
- `verynginx/api/controllers/config.lua` —— `/summary` 读 `host` 参数并校验
- `verynginx/api/controllers/plugins.lua` —— `/stats/top-paths` 读 host、新增 `/stats/hosts`

前端：
- `verynginx/dashboard/index.html` —— host 下拉
- `verynginx/dashboard/vn-dashboard.js` —— loadHosts + loadStats/loadTopPaths 带 host

配置：
- `verynginx/configs/config.default.json` —— `statistics.max_hosts`

测试：
- `test/v2/phase0/statistics_host_spec.lua` —— 新增：host 归一化、report 聚合/过滤、uri 预算均分、restore 版本号跳过

## 10. 风险与验证

- **dict 容量**：20m 上限，依赖 §6 的 uri 预算。实现后跑一次「50 host × 高基数 URI」压测确认 `no memory` 不出现（`dict_guard` 会 WARN）。
- **聚合开销**：host 空时 report 要遍历所有 host 的 index 合并，host 数受 max_hosts 限，可控。
- **采样偏差**：1/10 采样不变，host 维度同样采样，语义一致。
- 验证点：`nginx -t`、面板 host 下拉、`/summary?host=x` 返回只含 x、老接口不带 host 行为不变。
