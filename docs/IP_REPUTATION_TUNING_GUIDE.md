# IP 声誉引擎生产调优指南

> **目标**：帮助运维团队在不同流量规模下配置合理的参数，快速排查误报，避免常见配置陷阱。

---

## 一、参数推荐值（按流量规模）

### 1.1 小型站点（< 100 QPS）

```json
{
  "ip_reputation": {
    "enable": true,
    "threshold": 30,
    "window_size": 300,
    "slot_size": 60,
    "min_requests": 5,
    "flag_duration": 900,
    "pending_ttl": 600,
    "signals": {
      "waf_challenge": 3,
      "waf_block": 5,
      "not_found": 1,
      "challenge_fail": 5
    }
  }
}
```

| 参数 | 值 | 说明 |
|------|-----|------|
| `threshold` | 30 | 稍高阈值避免 NAT 误杀 |
| `min_requests` | 5 | 小站点需要更多样本才能判定 |
| `flag_duration` | 900 | 稍长冷却期减少重复挑战 |
| `window_size` | 300 | 5 分钟滑动窗口 |

### 1.2 中型站点（100 ~ 1000 QPS）

```json
{
  "ip_reputation": {
    "enable": true,
    "threshold": 25,
    "window_size": 300,
    "slot_size": 60,
    "min_requests": 3,
    "flag_duration": 600,
    "pending_ttl": 600,
    "signals": {
      "waf_challenge": 3,
      "waf_block": 5,
      "not_found": 1,
      "challenge_fail": 5
    }
  }
}
```

这是默认配置，适合大多数生产环境。

### 1.3 大型 / 高并发站点（1000+ QPS）

```json
{
  "ip_reputation": {
    "enable": true,
    "threshold": 20,
    "window_size": 180,
    "slot_size": 30,
    "min_requests": 2,
    "flag_duration": 300,
    "pending_ttl": 300,
    "signals": {
      "waf_challenge": 2,
      "waf_block": 4,
      "not_found": 1,
      "challenge_fail": 4
    }
  }
}
```

| 参数 | 值 | 说明 |
|------|-----|------|
| `threshold` | 20 | 更低阈值快速拦截扫描器 |
| `window_size` | 180 | 3 分钟窗口更快响应 |
| `slot_size` | 30 | 更细粒度的时间切片 |
| `min_requests` | 2 | 大流量下样本充足 |
| `flag_duration` | 300 | 短冷却期避免长期误拦 |

### 1.4 API 网关（无浏览器用户）

```json
{
  "ip_reputation": {
    "enable": true,
    "threshold": 15,
    "window_size": 120,
    "slot_size": 30,
    "min_requests": 2,
    "flag_duration": 180,
    "pending_ttl": 120,
    "signals": {
      "waf_challenge": 2,
      "waf_block": 3,
      "not_found": 1,
      "challenge_fail": 3
    }
  }
}
```

> **注意**：API 场景没有浏览器执行 JS challenge，challenge 机制基本无效。建议：
> - 关闭 `browser_verify` 插件
> - 调低 threshold 让 block 规则直接生效
> - 依赖频率限制（frequency_limit）替代 challenge

---

## 二、误报排查流程

### 2.1 判断是否为误报

```
用户被封禁（403）
    │
    ├─ 查看 Audit Log → 记录封锁原因（waf_block / auto-flag）
    │
    ├─ 查看 IP Reputation 页面 → 该 IP 的信号历史
    │   ├─ 主要是 waf_challenge？ → 可能是正常用户触发了扫描规则
    │   ├─ 主要是 waf_block？ → 可能是真实攻击（SQLi/RCE）
    │   └─ 主要是 not_found？ → 可能是爬虫/扫描器探测
    │
    └─ 检查请求路径
        ├─ 集中在 /api/、/ → 可能是正常用户的攻击性请求
        └─ 分散在大量不存在的路径 → 大概率是扫描器
```

### 2.2 NAT 共享用户 vs 真实扫描器

| 特征 | NAT 共享用户 | 真实扫描器 |
|------|-------------|-----------|
| User-Agent 多样性 | 多种 UA（Chrome/Safari/Firefox） | 单一 UA（python-requests/curl） |
| 请求路径集中度 | 集中在业务相关路径 | 大量分散的路径探测 |
| 请求频率 | 突发尖峰后平静 | 持续高频扫描 |
| `distinct_ua_count` | 高（≥3） | 低（=1） |
| HTTP 方法分布 | 以 GET 为主，少量 POST | 大量 HEAD/OPTIONS 探测 |
| 是否通过 JS challenge | 通过 | 失败或无法执行 |

### 2.3 排查命令

```bash
# 在 nginx 机器上查看某 IP 的实时分数
curl -s http://localhost/verynginx/api/stats/ip-reputation/lookup?ip=x.x.x.x \
  -H "Cookie: verynginx_session=xxx"

# 查看某 IP 的信号明细
curl -s http://localhost/verynginx/api/stats/ip-reputation/flagged \
  -H "Cookie: verynginx_session=xxx" | jq '.data[] | select(.ip=="x.x.x.x")'

# 临时解除封禁
curl -X POST http://localhost/verynginx/api/stats/ip-reputation/clear \
  -H "Cookie: verynginx_session=xxx" \
  -d '{"ip":"x.x.x.x"}'

# 加入白名单（永久）
curl -X POST http://localhost/verynginx/api/stats/ip-reputation/whitelist/add \
  -H "Cookie: verynginx_session=xxx" \
  -d '{"entry":"x.x.x.x/32"}'
```

### 2.4 降低误调的参数调整策略

| 场景 | 调整方向 |
|------|---------|
| NAT 用户频繁被封 | 提高 `threshold`（+5），提高 `min_requests`（+2） |
| 扫描器漏网 | 降低 `threshold`（-5），降低 `waf_challenge` 权重 |
| 404 扫描误报正常用户 | 降低 `not_found` 权重（设为 0 或 1） |
| challenge 失败率过高 | 检查 `pending_ttl` 是否过短（见第三节） |

---

## 三、pending_ttl 与 cookie Max-Age 协同

### 3.1 当前默认值

| 参数 | 文件路径 | 默认值 |
|------|---------|--------|
| `pending_ttl` | `config.json` → `ip_reputation.pending_ttl` | 600（秒） |
| cookie `Max-Age` | `plugin/browser_verify/cookie_verify.lua` | 600（秒） |
| JS cookie `Max-Age` | `plugin/browser_verify/javascript_verify.lua` | 600（秒） |

### 3.2 三者关系

```
用户触发 challenge
    │
    ├─ set_pending(ip, pending_ttl)        ← 服务端 pending 状态过期时间
    ├─ Set-Cookie: Max-Age=600             ← 浏览器 cookie 过期时间
    └─ 用户执行 JS → 获得 cookie → 后续请求带 cookie
```

### 3.3 修改注意事项

**规则：`pending_ttl` ≥ cookie `Max-Age`**

| 情况 | 后果 |
|------|------|
| `pending_ttl` < cookie Max-Age | 服务端已清除 pending，但浏览器仍持 cookie → 用户被重复挑战 |
| `pending_ttl` > cookie Max-Age | cookie 过期 → 浏览器删除 → 服务端仍有 pending → 用户需重新获取 cookie（可接受） |
| `pending_ttl` = cookie Max-Age | 理想状态，两端同步过期 |

**修改流程**：

1. **修改 `pending_ttl`**：编辑 `config.json` → `ip_reputation.pending_ttl`，保存后重载 nginx
2. **修改 cookie `Max-Age`**：需要同时修改两个文件：
   - `verynginx/plugin/browser_verify/cookie_verify.lua` 第 52 行
   - `verynginx/plugin/browser_verify/javascript_verify.lua` 第 89 行
3. **修改后**：执行 `nginx -s reload` 使新配置生效
4. **验证**：通过 `curl` 触发 challenge，检查 `Set-Cookie` 头的 `Max-Age`

### 3.4 不同场景的推荐组合

| 场景 | `pending_ttl` | cookie `Max-Age` | 说明 |
|------|--------------|-----------------|------|
| 默认生产环境 | 600 | 600 | 10 分钟有效期 |
| 高安全场景 | 300 | 300 | 5 分钟，更快过期 |
| 开发/测试 | 3600 | 3600 | 1 小时，减少频繁挑战 |
| 公开 API | 不建议使用 challenge | - | API 客户端无法执行 JS |

---

## 四、监控与告警

### 4.1 Prometheus 指标

部署后可通过 `/metrics` 端点采集以下指标：

```
# 当前被标记的扫描器数量
ip_reputation_flagged_total

# 当前 pending challenge 的 IP 数
ip_reputation_pending_total

# 每日新增标记数
ip_reputation_flagged_today

# Top 5 被标记 IP 的分数
ip_reputation_score{ip="x.x.x.x"}

# 累计下发的 challenge 次数（counter）
ip_reputation_challenge_served_total

# ip_reputation 共享字典使用率
shared_dict_usage_pct{dict="ip_reputation"}
```

### 4.2 推荐告警规则

```yaml
# 告警：标记 IP 数突增（可能遭受扫描攻击）
- alert: IPReputationSpike
  expr: delta(ip_reputation_flagged_today[1h]) > 50
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "IP reputation flagged {{ $value }} IPs in last hour"

# 告警：pending 积压（challenge 可能失效）
- alert: IPPendingBacklog
  expr: ip_reputation_pending_total > 1000
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "{{ $value }} IPs in pending challenge state"

# 告警：共享字典接近容量上限
- alert: IPReputationDictNearFull
  expr: shared_dict_usage_pct{dict="ip_reputation"} > 80
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "ip_reputation shared dict {{ $full }}% full"
```

---

## 五、常见问题

### Q: 为什么正常用户收到 403？

**排查步骤**：
1. 在 IP Reputation 页面搜索该 IP
2. 查看信号历史和 UA 多样性
3. 如果 `distinct_ua_count` 高且路径集中在业务接口 → 大概率是误判
4. 临时处理：将 IP 加入白名单
5. 长期处理：提高 `threshold` 或 `min_requests`

### Q: 为什么扫描器没被拦截？

**排查步骤**：
1. 确认 `ip_reputation.enable = true`
2. 查看该 IP 的分数是否低于 `threshold`
3. 检查 `min_requests` 是否设置过高
4. 确认 `not_found` 权重 > 0（如果扫描器主要发 404 请求）

### Q: challenge 页面不弹出？

**排查步骤**：
1. 检查浏览器控制台是否有 JS 错误
2. 确认 `browser_verify` 插件已启用
3. 检查 challenge 规则的 `enable` 状态
4. 查看 `pending_ttl` 是否过短（用户还没打开页面就过期了）

### Q: 如何批量导入白名单？

```bash
# 通过 API 批量添加
for ip in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
  curl -X POST http://localhost/verynginx/api/stats/ip-reputation/whitelist/add \
    -H "Cookie: verynginx_session=xxx" \
    -d "{\"entry\":\"$ip\"}"
done
```

### Q: 共享字典满了怎么办？

- 增加 `nginx.conf` 中 `lua_shared_dict ip_reputation` 的大小（默认 16MB）
- 缩短 `flag_duration` 让过期条目更快清除
- 减少 `max_uri_keys`（statistics 插件）
