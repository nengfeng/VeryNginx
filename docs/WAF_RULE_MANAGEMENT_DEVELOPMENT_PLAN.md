# VeryNginx v2 WAF 规则管理系统 - 开发计划

> 基于 `docs/WAF_RULE_MANAGEMENT_DESIGN.md` 设计文档  
> 计划周期：约 6 天（4 阶段，13 个步骤）  
> 文件清单：12 个文件（1 新建，7 修改，2 测试，1 迁移，1 文档）

---

## 总览

```
阶段一 (2天) ─── 核心模块
  ├── Step 1: waf-rule-manager.lua (新建)
  ├── Step 2: filter/init.lua (改造)
  ├── Step 3: api/init.lua (新增路由)
  ├── Step 4: core/config.lua (schema扩展)
  └── Step 5: core/init.lua (集成)

阶段二 (2天) ─── Dashboard 前端
  ├── Step 6: dashboard/index.html (WAF页面)
  └── Step 7: 规则编辑器/测试工具

阶段三 (1天) ─── 高级功能
  ├── Step 8: 统计API
  └── Step 9: 集成测试

阶段四 (1天) ─── 迁移与文档
  ├── Step 10: filter/rules.lua (迁移)
  ├── Step 11: 清理旧代码
  ├── Step 12: 测试
  └── Step 13: API文档
```

---

## 阶段一：核心功能（预计 2 天）

### Step 1: 创建 `verynginx/waf-rule-manager.lua`（新建）

**依赖**：无（独立模块）

**需要实现的函数**（按调用链排列）：

| # | 函数 | 依赖 | 说明 |
|---|------|------|------|
| 1.1 | `chunk_rules(rules)` | 无 | 私有函数，规则数组分片（每片100条） |
| 1.2 | `unchunk_rules(chunks)` | 无 | 私有函数，合并分片为规则数组 |
| 1.3 | `deep_copy(t, depth)` | 无 | 私有函数，递归深拷贝（深度上限100） |
| 1.4 | `load_rules()` | `chunk_rules`, `load_from_file` | 优先 shared dict 分片，fallback 文件 |
| 1.5 | `load_from_file()` | 无 | 从 JSON 文件读取 `{version, timestamp, rules=[...]}` |
| 1.6 | `save_rules(rules)` | `chunk_rules`, `record_history`, `prune_backups` | 原子写入 + 分片缓存 + 备份 |
| 1.7 | `record_history(rules, version, timestamp)` | `deep_copy` | 记录完整规则快照到 history JSON |
| 1.8 | `get_history(limit)` | 无 | 返回最近 N 条变更记录 |
| 1.9 | `create_rule(rule)` | `validate_rule`, `generate_id`, `load_rules`, `save_rules` | 创建新规则 |
| 1.10 | `update_rule(rule_id, updates)` | `merge_rule`, `load_rules`, `save_rules` | 更新规则（保留统计字段） |
| 1.11 | `delete_rule(rule_id)` | `load_rules`, `save_rules` | 删除规则 |
| 1.12 | `merge_rule(rule, updates)` | 无 | 合并规则字段，保留运行时统计 |
| 1.13 | `generate_id(name)` | `core.random` | 生成 `{prefix}_{timestamp}_{hex8}` 格式ID |
| 1.14 | `validate_rule(rule)` | 无 | 完整字段验证（名称/分类/严重级别/动作/匹配器/状态码/速率限制） |
| 1.15 | `test_rule(rule, test_cases)` | `create_mock_context`, `matcher.test` | 批量测试规则匹配 |
| 1.16 | `create_mock_context(case)` | 无 | 创建模拟请求上下文 |
| 1.17 | `record_hit(rule_id, ctx)` | 无 | 管道分隔格式写入 hit buffer（异步） |
| 1.18 | `flush_hit_stats()` | 无 | 消费 buffer，聚合统计，写回 shared dict |
| 1.19 | `init_worker()` | `flush_hit_stats` | 启动 `ngx.timer.every(30)` 定时刷新 |
| 1.20 | `check_rate_limit(rule_id, rule)` | 无 | shared dict `incr` 实现滑动窗口 |
| 1.21 | `rollback(rule_id, target_version)` | `get_history`, `save_rules` | 从历史记录恢复完整规则集 |

**关键设计要点**：
- 所有 shared dict key 使用 `waf_rules:chunk:N` 分片前缀
- hit buffer 使用 head/tail 指针模式（双索引计数器）
- 文件写入使用 tmp+rename 原子模式
- 备份保留最近 10 个，自动清理旧备份
- `prune_backups()` 使用 `io.popen('ls -1t ...')` 扫描备份文件

**文件路径**：`verynginx/waf-rule-manager.lua`  
**Lua 路径要求**：该文件应放在 Lua 搜索路径下。需在 nginx 配置或 `package.path` 中添加：
```nginx
lua_package_path "/opt/verynginx/verynginx/?.lua;;";
```

---

### Step 2: 改造 `verynginx/plugin/filter/init.lua`

**依赖**：Step 1（需要 waf-rule-manager 模块）

**所需变更**：

```diff
- local config = require "core.config"
- local matcher = require "matcher.init"
+ local config = require "core.config"
+ local matcher = require "matcher.init"
+ local waf_manager = require "waf-rule-manager"

  function _M.on_access(ctx)
-     local rules = config.rule and config.rule.filter
-     if not rules then
-         return
-     end
+     local rules_obj = waf_manager.load_rules()
+     if not rules_obj then return end
+     local rules = rules_obj.rules
+     if not rules or #rules == 0 then return end

      for _, rule in ipairs(rules) do
          if rule.enable == false then
              goto continue
          end

          local matcher_def = matcher.resolve(rule)
          if not matcher_def then
              goto continue
          end

          local matched = matcher.test(matcher_def, ctx)
          if not matched then
              goto continue
          end

+         -- 速率限制检查（仅对匹配的请求生效）
+         if not waf_manager.check_rate_limit(rule.id, rule) then
+             goto continue
+         end
+
+         -- 记录命中统计
+         waf_manager.record_hit(rule.id, ctx)
+
          if rule.action == "accept" then
              ctx.set_action(ctx, "accept")
              return
          elseif rule.action == "block" then
              ctx.set_data(ctx, "filter:blocked", true)
              ctx.set_action(ctx, "block", {
                  code = rule.code or 403,
                  response = rule.response
              })
              return
+         elseif rule.action == "log" then
+             ngx.log(ngx.WARN, "waf: rule matched [", rule.id, "] ", rule.name, " uri=", ctx.request.uri)
          end
          ::continue::
      end
  end
```

**关键变更点**：
1. 从 `config.rule.filter` 改为 `waf_manager.load_rules()`
2. 新增 `check_rate_limit` 调用（在匹配之后）
3. 新增 `record_hit` 调用
4. 新增 `log` 动作处理
5. 规则数据格式从 `config.rule.filter` 转换为 `{version, timestamp, rules=[...]}`

---

### Step 3: 新增 `verynginx/api/init.lua` 路由

**依赖**：Step 1（waf-rule-manager 的 CRUD 函数）

**新增路由**（12 个）：

```lua
-- WAF 规则管理
_M.register("GET",    "/waf/rules",              handle_list_waf_rules,     true)
_M.register("POST",   "/waf/rules",              handle_create_waf_rule,    true)
_M.register("GET",    "/waf/rules/:id",          handle_get_waf_rule,       true)
_M.register("PUT",    "/waf/rules/:id",          handle_update_waf_rule,    true)
_M.register("DELETE", "/waf/rules/:id",          handle_delete_waf_rule,    true)
_M.register("POST",   "/waf/rules/:id/enable",   handle_enable_waf_rule,   true)
_M.register("POST",   "/waf/rules/:id/disable",  handle_disable_waf_rule,  true)
_M.register("POST",   "/waf/rules/test",         handle_test_waf_rule,      true)
_M.register("POST",   "/waf/rules/reload",       handle_reload_waf_rules,   true)
_M.register("GET",    "/waf/rules/history",      handle_waf_rule_history,   true)
_M.register("POST",   "/waf/rules/rollback",     handle_rollback_waf_rules, true)
_M.register("GET",    "/waf/stats",              handle_waf_stats,          true)
_M.register("GET",    "/waf/stats/:id",          handle_waf_rule_stats,     true)
```

**需要新增的 Handler 函数**（13 个）：

| Handler | 调用 waf-manager | 说明 |
|---------|-----------------|------|
| `handle_list_waf_rules` | `load_rules()` + 分类/严重级别过滤 + 分页 | 支持 `category`, `severity`, `page`, `limit` 查询参数 |
| `handle_create_waf_rule` | `create_rule(rule)` | 从请求体解析规则，返回新规则 ID |
| `handle_get_waf_rule` | `load_rules()` | 按 ID 查找单条规则，返回完整信息 |
| `handle_update_waf_rule` | `update_rule(id, updates)` | 部分更新，返回新版本号 |
| `handle_delete_waf_rule` | `delete_rule(id)` | 删除规则 |
| `handle_enable_waf_rule` | `update_rule(id, {enable=true})` | 快捷启用 |
| `handle_disable_waf_rule` | `update_rule(id, {enable=false})` | 快捷禁用 |
| `handle_test_waf_rule` | `test_rule(rule, test_cases)` | 批量测试，返回 `{passed, total, results}` |
| `handle_reload_waf_rules` | `load_from_file()` | 强制从 JSON 文件重新加载 |
| `handle_waf_rule_history` | `get_history(limit)` | 返回最近 N 条变更记录 |
| `handle_rollback_waf_rules` | `rollback(rule_id, version)` | 回滚到指定版本 |
| `handle_waf_stats` | `load_rules()` + 共享 dict 统计 | 聚合统计信息 |
| `handle_waf_rule_stats` | 单个规则统计 | 返回单条规则的统计信息 |

**关键设计要点**：
- 统一响应格式：`{ret="success"/"error", data=..., message=...}`
- 分页格式：`{page, limit, total, total_pages}`
- `handle_list_waf_rules` 需返回 `categories` 字段（各分类规则计数）
- `handle_test_waf_rule` 使用 `create_mock_context` 创建模拟请求
- 所有操作需记录 audit log

---

### Step 4: 扩展 `verynginx/core/config.lua` schema

**依赖**：无

**所需变更**：

```diff
  _M.schema = {
      version = "2.0",
      fields = {
          base_uri = { type = "string", default = "/verynginx" },
          ...
+         waf_rules = { type = "table", default = {} },
      }
  }
```

添加 `waf_rules` 字段到 schema，默认值为空表 `{}`。

---

### Step 5: 集成 `verynginx/core/init.lua`

**依赖**：Step 1（waf-rule-manager.init_worker）

**所需变更**：

```diff
  function _M.init_worker()
      local metrics = require "core.metrics"
      local observability = require "core.observability"
      local statistics = require "core.statistics"
      local health_check = require "plugin.proxy_pass.health_check"
+     local waf_manager = require "waf-rule-manager"

      metrics.init()
      observability.init()
      statistics.init()
      health_check.init()
+     waf_manager.init_worker()
  end
```

---

## 阶段二：Dashboard 前端（预计 2 天）

### Step 6: Dashboard WAF 规则管理页面

**依赖**：Step 3（API 路由已注册）

**在 `verynginx/dashboard/index.html` 中新增**：

**导航栏新增标签**：
```html
<a :class="{active: page==='waf'}" @click="page='waf';loadWafRules()">WAF 规则</a>
```

**新增页面组件**（Vue 3）：

| 组件 | 功能 | API 调用 |
|------|------|----------|
| `waf-rule-list` | 规则列表（分类筛选、分页、启用/禁用切换） | `GET /waf/rules`, `POST /waf/rules/:id/enable\|disable` |
| `waf-rule-editor` | 规则编辑器（表单 + JSON 编辑） | `PUT /waf/rules/:id`, `DELETE /waf/rules/:id` |
| `waf-rule-create` | 新建规则（表单 + JSON 编辑） | `POST /waf/rules` |
| `waf-rule-tester` | 规则测试工具（批量测试用例） | `POST /waf/rules/test` |
| `waf-stats` | 统计概览（卡片 + 按分类/严重级别统计） | `GET /waf/stats` |
| `waf-rule-history` | 变更历史（版本列表 + 回滚按钮） | `GET /waf/rules/history`, `POST /waf/rules/rollback` |

**关键 UI 设计**：
- 左侧分类筛选面板（复选框）
- 规则列表行可点击展开详情
- 命中数带 formatNumber 格式化显示
- 编辑器支持标签输入（输入后回车添加）
- 测试结果使用绿色/红色标记通过/失败
- 删除操作需要二次确认弹窗

---

## 阶段三：高级功能（预计 1 天）

### Step 7: 统计 API 完善

**依赖**：Step 1（统计相关函数已在 waf-rule-manager.lua 中）

**需要实现**：

1. `handle_waf_stats`：从 shared dict 读取 `waf_rule_stats:*` 前缀的所有 key
2. 聚合计算：总规则数、启用规则数、总命中数、今日命中数
3. 按分类/严重级别分组统计
4. Top 10 规则排名
5. 最近 50 条触发记录
6. `handle_waf_rule_stats`：单条规则的统计详情

**关键实现**：
- 使用 `shared:get_keys(STATS_PREFIX .. "*")` 获取所有统计 key（注意性能，避免在热路径调用）
- 今日命中数：比较 `last_triggered` 与当天 0 点时间戳
- Top 规则按 `hit_count` 降序排列

---

### Step 8: 集成测试

**依赖**：Steps 1-7 全部完成

**测试文件**：

1. `test/v2/spec/waf_rule_manager_spec.lua`（busted 单元测试）

| 测试用例 | 测试范围 |
|---------|---------|
| `chunk_rules / unchunk_rules` | 分片/合并一致性和边界条件 |
| `load_rules / save_rules` | 原子写入 + 共享 dict 分片缓存 |
| `create_rule / update_rule / delete_rule` | CRUD 操作 |
| `validate_rule` | 所有验证规则（必填/长度/范围/枚举） |
| `test_rule` | 模拟上下文匹配测试 |
| `check_rate_limit` | 速率限制计数 |
| `record_hit / flush_hit_stats` | 异步缓冲统计 |
| `rollback` | 回滚到指定版本 |
| `generate_id` | ID 格式验证 |
| `merge_rule` | 字段合并和统计保留 |

2. `test/v2/test_integration.py`（补充测试）

| 测试用例 | 测试范围 |
|---------|---------|
| API 认证 | 所有 WAF 端点需 auth |
| CRUD 流程 | 创建→查询→更新→删除 |
| 分页 | page/limit 参数 |
| 规则测试端点 | POST /waf/rules/test |
| 历史/回滚 | 创建后回滚 |
| 统计 | GET /waf/stats |

---

## 阶段四：迁移与文档（预计 1 天）

### Step 9: 迁移 `verynginx/plugin/filter/rules.lua`

**依赖**：Step 1（waf-rule-manager 已可用）

**迁移脚本位置**：`docs/migrations/migrate_waf_rules.lua`

**迁移步骤**：
1. 运行迁移脚本，将 `rules.lua` 中的默认规则转换为 `config.json` 格式
2. 保留 `rules.lua` 作为 fallback（当 `load_rules()` 返回空时的默认规则）
3. 修改 `rules.lua` 的 `load_rules()` 函数，优先从 config 读取

### Step 10: 清理旧代码

1. 删除 `filter/rules.lua` 中的 hardcoded 规则（保留 fallback 结构）
2. 移除 `config.lua` 中不再使用的旧 filter 引用（如果有）
3. 确认 `on_access.lua` 流程不受影响

### Step 11: 完整测试

1. `busted test/v2/` 运行所有单元测试
2. `python test/v2/test_integration.py` 运行集成测试
3. Dashboard 手动测试：WAF 页面 → 创建规则 → 测试 → 保存 → 查看统计

### Step 12: API 文档

创建 `docs/WAF_API.md`，包含：
- 所有端点的请求/响应格式
- 错误码定义
- 限流说明
- 使用示例

---

## 详细步骤依赖图

```
Step 1 (waf-rule-manager.lua)
  ├── Step 2 (filter/init.lua)
  ├── Step 3 (api/init.lua) 
  │     └── Step 6 (Dashboard)
  ├── Step 5 (core/init.lua)
  └── Step 9 (rules.lua 迁移)
  
Step 4 (config schema) — 独立，随时可做

Step 7 (统计 API) — Step 1 完成后可做

Step 8 (集成测试) — Steps 1-7 全部完成后

Step 10 (代码清理) — Step 9 完成后

Step 11 (完整测试) — 所有修改完成后

Step 12 (API 文档) — API 稳定后
```

---

## 文件变更清单

| 文件 | 操作 | 预计行数 | 说明 |
|------|------|---------|------|
| `verynginx/waf-rule-manager.lua` | **新建** | ~400 行 | 核心管理器 |
| `verynginx/plugin/filter/init.lua` | 修改 | ~15 行 | 切换数据源、新增 rate_limit/统计/log |
| `verynginx/api/init.lua` | 修改 | ~350 行 | 13 个新 handler |
| `verynginx/core/config.lua` | 修改 | ~1 行 | 新增 schema 字段 |
| `verynginx/core/init.lua` | 修改 | ~3 行 | 添加 init_worker 调用 |
| `verynginx/dashboard/index.html` | 修改 | ~400 行 | WAF 管理界面 |
| `verynginx/plugin/filter/rules.lua` | 修改 | ~20 行 | 改为 fallback 模式 |
| `docs/migrations/migrate_waf_rules.lua` | 新建 | ~60 行 | 迁移脚本 |
| `docs/WAF_API.md` | 新建 | ~100 行 | API 文档 |
| `test/v2/spec/waf_rule_manager_spec.lua` | 新建 | ~200 行 | 单元测试 |
| `test/v2/test_integration.py` | 修改 | ~150 行 | 补充集成测试 |

**总计**：约 1700 行新增代码，12 个文件（4 新建，7 修改，1 文档）

---

## 风险管理

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| shared dict 分片加载性能 | 大量规则时多个 `get` 调用 | 分片大小调整为 200；考虑添加 `load_rules_meta_only()` |
| `prune_backups` 的 `io.popen` | 执行外部命令 | 改为纯 Lua 文件扫描 |
| `shared:get_keys()` 在大数据量时性能差 | 统计 API 可能慢 | 统计使用聚合计数器，避免 `get_keys` |
| JSON 文件并发写入 | nginx worker 竞争 | 使用 `config_save_lock_ttl` 类似机制或 worker 互斥 |
| `luarocks dkjson` 不可用 | 模块加载失败 | 项目已有内置 `lua_script/module/dkjson.lua`，确保 path 正确 |

---

## 验收标准

1. **热加载**：通过 API 创建规则后，下一次请求立即生效
2. **版本回滚**：创建 3 个版本后回滚到版本 1，规则恢复
3. **规则测试**：SQL 注入规则对正常请求不触发，对恶意请求触发
4. **速率限制**：同一 IP 在窗口内超过 max_hits 后被限速
5. **统计准确**：规则命中数在 Dashboard 显示正确
6. **迁移**：现有规则迁移后行为不变
7. **测试覆盖**：busted 覆盖率 > 80%
8. **性能**：规则匹配耗时 < 10ms（1000 条规则下）
