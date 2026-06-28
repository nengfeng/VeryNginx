# VeryNginx v2 WAF 规则管理系统设计方案

> **版本**: v1.0  
> **日期**: 2026-06-28  
> **状态**: 设计阶段

---

## 目录

1. [架构概述](#1-架构概述)
2. [数据模型](#2-数据模型)
3. [存储策略](#3-存储策略)
4. [API 设计](#4-api-设计)
5. [核心模块设计](#5-核心模块设计)
6. [Dashboard UI 设计](#6-dashboard-ui-设计)
7. [安全考虑](#7-安全考虑)
8. [实施计划](#8-实施计划)
9. [迁移策略](#9-迁移策略)
10. [总结](#10-总结)

---

## 1. 架构概述

### 1.1 设计目标

- **规则热更新**：无需重启即可添加/修改/删除规则
- **完整元数据**：每条规则包含描述、分类、严重级别、标签等
- **版本控制**：自动记录变更历史，支持回滚
- **规则测试**：上线前可验证规则是否按预期工作
- **运行时统计**：命中次数、最后触发时间、按类别统计
- **条件组合**：支持 AND/OR 逻辑组合多个条件
- **速率限制**：每条规则可独立配置速率限制

### 1.2 架构图

```
┌─────────────────────────────────────────────────────────────┐
│                      Dashboard (前端)                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │ 规则列表    │ │ 规则编辑器  │ │ 测试工具    │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    API Layer (api/init.lua)                  │
│  GET    /waf/rules              获取所有规则                  │
│  POST   /waf/rules              创建新规则                    │
│  GET    /waf/rules/:id          获取单条规则                  │
│  PUT    /waf/rules/:id          更新规则                      │
│  DELETE /waf/rules/:id          删除规则                      │
│  POST   /waf/rules/:id/enable   启用规则                      │
│  POST   /waf/rules/:id/disable  禁用规则                      │
│  POST   /waf/rules/test         测试规则                      │
│  POST   /waf/rules/reload       热重载规则                    │
│  GET    /waf/rules/history      获取变更历史                  │
│  POST   /waf/rules/rollback     回滚到指定版本                │
│  GET    /waf/stats              获取统计信息                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              WAF Rule Manager (waf-rule-manager.lua)         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │ 规则加载器  │ │ 规则验证器  │ │ 版本控制器  │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │ 规则执行器  │ │ 统计收集器  │ │ 速率限制器  │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Storage Layer                             │
│  ┌─────────────────────┐  ┌─────────────────────┐           │
│  │  Shared Dict        │  │  JSON Files         │           │
│  │  (运行时缓存)       │  │  (持久化存储)       │           │
│  │  - waf_rules:meta   │  │  - waf-rules.json   │           │
│  │  - waf_rules:chunk:*│  │  - waf-rules-history│           │
│  │  - waf_rule_stats   │  │  - waf-rules-backup │           │
│  └─────────────────────┘  └─────────────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 与现有系统的集成

| 现有模块 | 集成方式 |
|----------|----------|
| `core/config.lua` | 新增 `waf_rules` 字段到 schema，规则保存到 `config.json` |
| `matcher/init.lua` | 复用现有 matcher 体系，规则通过 `matcher.resolve()` 解析 |
| `plugin/filter/init.lua` | 改为从 WAF Rule Manager 加载规则，而非硬编码表 |
| `api/init.lua` | 新增 WAF 管理 API 路由 |
| `dashboard/index.html` | 新增 WAF 规则管理页面 |

---

## 2. 数据模型

### 2.1 规则 Schema

```json
{
  "id": "string (必填, 唯一标识)",
  "name": "string (必填, 规则名称)",
  "description": "string (可选, 规则描述)",
  "category": "string (必填, 规则分类)",
  "severity": "string (必填, 严重级别)",
  "enable": "boolean (默认 true)",
  "priority": "number (默认 100, 越小优先级越高)",

  "matcher": "string|table (必填, 匹配器定义)",
  "action": "string (必填, 动作: block|accept|log|challenge)",
  "code": "number (可选, HTTP 状态码)",
  "response": "string (可选, 响应模板名)",

  "conditions": {
    "logic": "string (AND|OR, 默认 AND)",
    "conditions": [
      {
        "type": "string (matcher|not_ip_whitelist|not_ua_blacklist)",
        "matcher": "string (当 type=matcher 时)",
        "ips": "table (当 type=not_ip_whitelist 时)",
        "uas": "table (当 type=not_ua_blacklist 时)"
      }
    ]
  },

  "rate_limit": {
    "enable": "boolean (默认 false)",
    "max_hits": "number (默认 10)",
    "window": "number (默认 60, 秒)",
    "action": "string (log|block, 默认 log)"
  },

  "tags": "table (可选, 标签列表)",

  "hit_count": "number (运行时统计, 默认 0)",
  "last_triggered": "number (运行时统计, 时间戳)",
  "last_matched_uri": "string (运行时统计)",

  "created_at": "string (ISO 8601)",
  "updated_at": "string (ISO 8601)",
  "created_by": "string (默认 admin)",
  "version": "number (默认 1)"
}
```

### 2.2 规则分类体系

| 分类 | 说明 | 默认严重级别 |
|------|------|-------------|
| `sqli` | SQL 注入攻击 | critical |
| `xss` | 跨站脚本攻击 | critical |
| `rce` | 远程代码执行 | critical |
| `lfi` | 本地文件包含 | high |
| `rfi` | 远程文件包含 | high |
| `path_traversal` | 路径遍历 | critical |
| `scanner` | 扫描器/爬虫 | medium |
| `bot` | 恶意爬虫 | medium |
| `brute` | 暴力破解 | high |
| `spam` | 垃圾信息 | low |
| `custom` | 自定义规则 | medium |

### 2.3 严重级别定义

| 级别 | 说明 | 默认动作 | 默认状态码 |
|------|------|----------|-----------|
| `critical` | 高危攻击，必须阻断 | block | 403 |
| `high` | 中高危攻击，建议阻断 | block | 403 |
| `medium` | 中危攻击，可记录+限速 | log | 429 |
| `low` | 低危攻击，仅记录 | log | 200 |

### 2.4 规则状态流转

```
┌─────────┐    enable    ┌─────────┐    disable    ┌─────────┐
│  draft  │ ──────────▶  │ enabled │ ──────────▶  │ disabled│
└─────────┘              └─────────┘              └─────────┘
     │                        │                        │
     │                        │                        │
     ▼                        ▼                        ▼
┌─────────┐              ┌─────────┐              ┌─────────┐
│  test   │              │ active  │              │  test   │
└─────────┘              └─────────┘              └─────────┘
```

---

## 3. 存储策略

### 3.1 双层存储架构

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Shared Dict (运行时缓存, 高频读取)                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Key: "waf_rules:meta" (版本/分片数)               │   │
│  │  Key: "waf_rules:chunk:1" (规则 1-100)             │   │
│  │  Key: "waf_rules:chunk:2" (规则 101-200)           │   │
│  │  Value: JSON string (所有规则的序列化)                │   │
│  │  TTL: 永不过期 (通过 reload 更新)                     │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Key: "waf_rules_version"                            │   │
│  │  Value: string (当前版本号)                          │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Key: "waf_rule_stats:{rule_id}"                     │   │
│  │  Value: JSON string (命中统计)                       │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Key: "waf_rate_limit:{rule_id}:{window}"           │   │
│  │  Value: number (当前窗口命中次数)                    │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ 定时同步 / 手动触发
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: JSON Files (持久化存储, 低频写入)                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  verynginx/configs/waf-rules.json                    │   │
│  │  - 当前生效的规则集                                   │   │
│  │  - 包含完整元数据                                    │   │
│  │  - 人类可读的 JSON 格式                              │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  verynginx/configs/waf-rules-history.json            │   │
│  │  - 变更历史记录 (最近 100 条)                        │   │
│  │  - 支持版本回滚                                      │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  verynginx/configs/waf-rules-backup-{timestamp}.json │   │
│  │  - 自动备份 (保存最近 10 个)                         │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 数据一致性保证

1. **写入流程**：
   - 先写入 JSON 文件（原子写入：tmp + rename）
   - 成功后更新 shared dict 缓存
   - 最后更新版本号

2. **读取流程**：
   - 优先从 shared dict 读取（高性能）
   - 如果 shared dict 无数据，从 JSON 文件加载并缓存

3. **恢复流程**：
   - nginx 启动时从 JSON 文件加载规则
   - 如果 JSON 文件损坏，从备份文件恢复
   - 如果所有文件损坏，使用默认硬编码规则

---

## 4. API 设计

### 4.1 路由定义

```lua
-- api/init.lua 新增路由
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

### 4.2 请求/响应格式

#### GET /waf/rules - 获取所有规则

**请求**：
```http
GET /waf/rules?category=sqli&severity=critical&page=1&limit=20
```

**响应**：
```json
{
  "ret": "success",
  "data": {
    "rules": [
      {
        "id": "sqli_001",
        "name": "SQL Injection - UNION SELECT",
        "description": "Detects UNION-based SQL injection",
        "category": "sqli",
        "severity": "critical",
        "enable": true,
        "priority": 100,
        "matcher": "attack_sqli",
        "action": "block",
        "code": 403,
        "response": "forbidden_json",
        "tags": ["sqli", "union"],
        "hit_count": 1523,
        "last_triggered": 1719576000,
        "last_matched_uri": "/api/users?id=1 UNION SELECT",
        "created_at": "2026-06-28T10:00:00Z",
        "updated_at": "2026-06-28T10:00:00Z",
        "version": 1
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 6,
      "total_pages": 1
    },
    "categories": {
      "sqli": 2,
      "xss": 1,
      "scanner": 1,
      "path_traversal": 1,
      "rce": 1
    }
  }
}
```

#### POST /waf/rules - 创建新规则

**请求**：
```json
{
  "name": "SQL Injection - INSERT SELECT",
  "description": "Detects INSERT-based SQL injection",
  "category": "sqli",
  "severity": "critical",
  "matcher": {
    "Args": {
      "name_operator": "*",
      "operator": "≈",
      "value": "\\binsert\\b.+\\bselect\\b",
      "on_body_error": "fail_closed"
    }
  },
  "action": "block",
  "code": 403,
  "response": "forbidden_json",
  "tags": ["sqli", "insert"],
  "rate_limit": {
    "enable": true,
    "max_hits": 5,
    "window": 60,
    "action": "log"
  }
}
```

**响应**：
```json
{
  "ret": "success",
  "data": {
    "id": "sqli_007",
    "name": "SQL Injection - INSERT SELECT",
    "created_at": "2026-06-28T12:00:00Z",
    "version": 1
  }
}
```

#### POST /waf/rules/test - 测试规则

**请求**：
```json
{
  "rule": {
    "matcher": {
      "URI": {
        "operator": "≈",
        "value": "(\\.\\./|\\.\\.\\\\)"
      }
    },
    "action": "block"
  },
  "test_cases": [
    {
      "name": "正常请求",
      "uri": "/api/users",
      "method": "GET",
      "expected": false
    },
    {
      "name": "路径遍历攻击",
      "uri": "/api/../../etc/passwd",
      "method": "GET",
      "expected": true
    },
    {
      "name": "编码绕过",
      "uri": "/api/%2e%2e/%2e%2e/etc/passwd",
      "method": "GET",
      "expected": true
    }
  ]
}
```

**响应**：
```json
{
  "ret": "success",
  "data": {
    "total": 3,
    "passed": 3,
    "failed": 0,
    "results": [
      {
        "name": "正常请求",
        "uri": "/api/users",
        "matched": false,
        "passed": true
      },
      {
        "name": "路径遍历攻击",
        "uri": "/api/../../etc/passwd",
        "matched": true,
        "passed": true
      },
      {
        "name": "编码绕过",
        "uri": "/api/%2e%2e/%2e%2e/etc/passwd",
        "matched": true,
        "passed": true
      }
    ]
  }
}
```

#### GET /waf/rules/history - 获取变更历史

**响应**：
```json
{
  "ret": "success",
  "data": [
    {
      "version": 5,
      "timestamp": "2026-06-28T12:05:00Z",
      "action": "update",
      "rule_count": 6,
      "rule_data": [
        {
          "id": "sqli_001",
          "name": "SQL Injection - UNION SELECT",
          "severity": "critical",
          "action": "block"
        }
      ]
    },
    {
      "version": 4,
      "timestamp": "2026-06-28T12:00:00Z",
      "action": "create",
      "rule_count": 5,
      "rule_data": [
        {
          "id": "sqli_001",
          "name": "SQL Injection - UNION SELECT",
          "severity": "high",
          "action": "block"
        }
      ]
    }
  ]
}
```

> 注：`rule_data` 为完整规则快照。列表接口可省略 `rule_data` 只返回元数据，详情接口返回完整数据。

#### POST /waf/rules/rollback - 回滚规则

**请求**：
```json
{
  "version": 3,
  "rule_id": "sqli_001"
}
```

**响应**：
```json
{
  "ret": "success",
  "message": "Rolled back to version 3"
}
```

#### GET /waf/stats - 获取统计信息

**响应**：
```json
{
  "ret": "success",
  "data": {
    "total_rules": 6,
    "enabled_rules": 5,
    "total_hits": 5234,
    "today_hits": 156,
    "by_category": {
      "sqli": { "rules": 2, "hits": 2345 },
      "scanner": { "rules": 1, "hits": 1234 },
      "path_traversal": { "rules": 1, "hits": 987 },
      "rce": { "rules": 1, "hits": 456 },
      "xss": { "rules": 1, "hits": 212 }
    },
    "by_severity": {
      "critical": { "rules": 3, "hits": 3456 },
      "high": { "rules": 2, "hits": 1234 },
      "medium": { "rules": 1, "hits": 544 }
    },
    "top_rules": [
      { "id": "sqli_001", "name": "SQL Injection - UNION SELECT", "hits": 1523 },
      { "id": "scanner_001", "name": "Scanner Detection", "hits": 1234 }
    ],
    "recent_triggers": [
      {
        "rule_id": "sqli_001",
        "uri": "/api/users?id=1 UNION SELECT",
        "ip": "192.168.1.100",
        "timestamp": 1719576000
      }
    ]
  }
}
```

---

## 5. 核心模块设计

### 5.1 waf-rule-manager.lua - 规则管理器

```lua
local _M = {}
local json = require("dkjson")
local config = require("core.config")
local matcher = require("matcher.init")

-- 规则缓存 key（分片存储，每片最多 100 条规则）
local CACHE_PREFIX = "waf_rules:chunk:"
local META_KEY = "waf_rules:meta"
local VERSION_KEY = "waf_rules_version"
local STATS_PREFIX = "waf_rule_stats:"
local RATE_PREFIX = "waf_rate_limit:"

-- 分片大小（每片最多规则数）
local CHUNK_SIZE = 100

-- 将规则数组分片
-- @param rules: 规则数组
-- @return table: { [chunk_index] = { rules: [...], count: n } }
local function chunk_rules(rules)
    local chunks = {}
    for i, rule in ipairs(rules) do
        local chunk_idx = math.ceil(i / CHUNK_SIZE)
        if not chunks[chunk_idx] then
            chunks[chunk_idx] = { rules = {}, count = 0 }
        end
        table.insert(chunks[chunk_idx].rules, rule)
        chunks[chunk_idx].count = chunks[chunk_idx].count + 1
    end
    return chunks
end

-- 合并分片为规则数组
-- @param chunks: 分片表
-- @return table: 规则数组
local function unchunk_rules(chunks)
    local rules = {}
    local sorted_keys = {}
    for k in pairs(chunks) do
        table.insert(sorted_keys, tonumber(k))
    end
    table.sort(sorted_keys)
    for _, k in ipairs(sorted_keys) do
        local chunk = chunks[tostring(k)]
        for _, rule in ipairs(chunk.rules) do
            table.insert(rules, rule)
        end
    end
    return rules
end

-- 深拷贝表（递归，含深度限制）
-- @param t: 源表
-- @param depth: 当前深度（内部使用）
-- @return table: 深拷贝后的表
local function deep_copy(t, depth)
    depth = depth or 0
    if depth > 100 then
        return {}
    end
    if type(t) ~= "table" then return t end
    local copy = {}
    for k, v in pairs(t) do
        copy[k] = deep_copy(v, depth + 1)
    end
    return copy
end

-- 加载规则（优先 shared dict 分片，fallback 文件）
-- @return table: { version, timestamp, rules = [...] } 或 nil
function _M.load_rules()
    local shared = ngx.shared.vn_config
    if shared then
        -- 从分片加载：先获取元数据，再拉取所有分片
        local meta_json = shared:get(META_KEY)
        if meta_json then
            local meta = json.decode(meta_json)
            if meta and meta.chunk_count and meta.chunk_count > 0 then
                local chunks = {}
                for i = 1, meta.chunk_count do
                    local chunk_json = shared:get(CACHE_PREFIX .. i)
                    if chunk_json then
                        local chunk = json.decode(chunk_json)
                        if chunk then
                            chunks[tostring(i)] = chunk
                        end
                    end
                end
                if next(chunks) then
                    return { version = meta.version, timestamp = meta.timestamp, rules = unchunk_rules(chunks) }
                end
            end
        end
    end
    -- fallback: 从文件加载（返回一致的 {version, timestamp, rules} 格式）
    return _M.load_from_file()
end

-- 保存规则（原子写入 + 分片缓存更新）
-- @param rules: 规则数组 [...]
function _M.save_rules(rules)
    -- 读取当前版本号并自增
    local shared = ngx.shared.vn_config
    local current_version
    if shared then
        current_version = shared:incr("waf_rules_save_version", 1, 0)
    else
        current_version = 1
    end

    -- 包装为 {version, timestamp, rules} 格式
    local data = {
        version = current_version,
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        rules = rules
    }

    -- 1. 写入 JSON 文件
    local path = config.resolve_path() .. "configs/waf-rules.json"
    local tmp_path = path .. ".tmp"
    local f = io.open(tmp_path, "w")
    if not f then return false, "cannot open temp file" end
    f:write(json.encode(data, { indent = true }))
    f:close()
    os.rename(tmp_path, path)

    -- 2. 更新 shared dict 分片缓存
    if shared then
        -- 分片存储规则
        local chunks = chunk_rules(rules)
        for idx, chunk in pairs(chunks) do
            shared:set(CACHE_PREFIX .. idx, json.encode(chunk))
        end
        -- 更新元数据
        local meta = {
            version = data.version,
            timestamp = data.timestamp,
            chunk_count = #chunks,
            rule_count = #rules,
            updated_at = ngx.time()
        }
        shared:set(META_KEY, json.encode(meta))
        shared:set(VERSION_KEY, tostring(data.version))
    end

    -- 3. 记录变更历史
    _M.record_history(rules, data.version, data.timestamp)

    return true
end

-- 记录变更历史
-- @param rules: 规则数组
-- @param version: 版本号（整数）
-- @param timestamp: 时间戳（ISO 8601）
function _M.record_history(rules, version, timestamp)
    local path = config.resolve_path() .. "configs/waf-rules-history.json"
    local f = io.open(path, "r")
    local history = {}
    if f then
        local content = f:read("*all")
        f:close()
        history = json.decode(content) or {}
    end

    -- 记录本次变更（保存完整规则快照）
    table.insert(history, {
        version = version,
        timestamp = timestamp,
        action = "update",
        rule_count = #rules,
        rule_data = deep_copy(rules)
    })

    -- 只保留最近 100 条
    if #history > 100 then
        local recent = {}
        for i = #history - 99, #history do
            table.insert(recent, history[i])
        end
        history = recent
    end

    -- 保存历史文件
    local tmp_path = path .. ".tmp"
    local wf = io.open(tmp_path, "w")
    if wf then
        wf:write(json.encode(history, { indent = true }))
        wf:close()
        os.rename(tmp_path, path)
    end
end

-- 获取变更历史
function _M.get_history(limit)
    local path = config.resolve_path() .. "configs/waf-rules-history.json"
    local f = io.open(path, "r")
    if not f then return {} end
    local content = f:read("*all")
    f:close()
    local history = json.decode(content) or {}
    -- 返回最近 N 条
    if limit and #history > limit then
        local recent = {}
        for i = #history - limit + 1, #history do
            table.insert(recent, history[i])
        end
        return recent
    end
    return history
end

-- 从文件加载规则
-- 始终返回 { version, timestamp, rules = [...] } 或 nil
-- version 为整数，timestamp 为 ISO 8601 字符串
function _M.load_from_file()
    local path = config.resolve_path() .. "configs/waf-rules.json"
    local f = io.open(path, "r")
    if not f then return nil end
    local content = f:read("*all")
    f:close()
    local data = json.decode(content)
    if not data then return nil end
    if data.rules then
        return { version = data.version or 1, timestamp = data.timestamp, rules = data.rules }
    end
    -- 兼容旧格式：数组直接作为 rules
    return { version = 1, timestamp = nil, rules = data }
end

-- 合并规则（将 updates 合并到 rule）
-- @param rule: 原始规则
-- @param updates: 更新内容
-- @return table: 合并后的规则
function _M.merge_rule(rule, updates)
    local merged = {}
    -- 复制原始规则
    for k, v in pairs(rule) do
        merged[k] = v
    end
    -- 应用更新（保留运行时统计）
    for k, v in pairs(updates) do
        if k ~= "hit_count" and k ~= "last_triggered" and k ~= "last_matched_uri" then
            merged[k] = v
        end
    end
    -- 恢复运行时统计
    merged.hit_count = rule.hit_count
    merged.last_triggered = rule.last_triggered
    merged.last_matched_uri = rule.last_matched_uri
    return merged
end

-- 创建模拟上下文（用于测试）
-- @param case: 测试用例
-- @return table: 模拟的 ctx
function _M.create_mock_context(case)
    local ctx = {
        request = {
            uri = case.uri or "/",
            method = case.method or "GET",
            remote_addr = case.ip or "127.0.0.1",
            host = case.host or "localhost",
            user_agent = case.ua or "Mozilla/5.0",
            referer = case.referer or "",
            scheme = "http",
            _body_args = nil,
            _body_read = false,
            _body_error = nil,
        },
        match_cache = {},
        match_cache_size = 0,
        action_result = nil,
        data = {},
        get_uri_args = function(self)
            local args = {}
            local qs = self.request.uri:match("%?(.*)")
            if qs then
                for k, v in qs:gmatch("([^&=]+)=([^&]*)") do
                    args[k] = v
                end
            end
            return args
        end,
        get_body_args = function(self)
            return self.request._body_args or {}
        end,
        set_action = function(self, action, data)
            self.action_result = { type = action, data = data }
        end,
        has_decision = function(self)
            return self.action_result ~= nil
        end,
        clear_action = function(self)
            self.action_result = nil
        end,
        set_data = function(self, k, v)
            self.data[k] = v
        end,
        get_data = function(self, k)
            return self.data[k]
        end,
    }
    return ctx
end

-- 创建规则
function _M.create_rule(rule)
    -- 验证规则
    local ok, err = _M.validate_rule(rule)
    if not ok then return false, err end

    -- 生成 ID
    rule.id = rule.id or _M.generate_id(rule.name)

    -- 检查 ID 是否重复
    local rules_obj = _M.load_rules()
    local rules = rules_obj and rules_obj.rules or {}
    for _, r in ipairs(rules) do
        if r.id == rule.id then
            return false, "rule id already exists: " .. rule.id
        end
    end

    -- 设置元数据
    rule.enable = rule.enable ~= false
    rule.priority = rule.priority or 100
    rule.created_at = os.date("!%Y-%m-%dT%H:%M:%SZ")
    rule.updated_at = rule.created_at
    rule.created_by = "admin"
    rule.version = 1
    rule.hit_count = 0

    -- 添加到规则集
    table.insert(rules, rule)

    -- 保存
    return _M.save_rules(rules)
end

-- 更新规则
function _M.update_rule(rule_id, updates)
    local rules_obj = _M.load_rules()
    local rules = rules_obj and rules_obj.rules or {}
    for i, r in ipairs(rules) do
        if r.id == rule_id then
            -- 保留运行时统计
            updates.hit_count = r.hit_count
            updates.last_triggered = r.last_triggered
            updates.last_matched_uri = r.last_matched_uri

            -- 更新元数据
            updates.updated_at = os.date("!%Y-%m-%dT%H:%M:%SZ")
            updates.version = (r.version or 1) + 1

            -- 合并规则
            local new_rule = _M.merge_rule(r, updates)
            rules[i] = new_rule

            -- 保存
            local ok, err = _M.save_rules(rules)
            if not ok then return false, err end

            return true, new_rule
        end
    end
    return false, "rule not found: " .. rule_id
end

-- 删除规则
function _M.delete_rule(rule_id)
    local rules_obj = _M.load_rules()
    local rules = rules_obj and rules_obj.rules or {}
    for i, r in ipairs(rules) do
        if r.id == rule_id then
            table.remove(rules, i)
            return _M.save_rules(rules)
        end
    end
    return false, "rule not found: " .. rule_id
end

-- 测试规则
function _M.test_rule(rule, test_cases)
    local results = {}
    for _, case in ipairs(test_cases) do
        -- 创建模拟上下文
        local ctx = _M.create_mock_context(case)
        local matched = matcher.test(rule.matcher, ctx)
        table.insert(results, {
            name = case.name,
            uri = case.uri,
            matched = matched,
            passed = matched == case.expected
        })
    end
    return results
end

-- 记录命中统计（异步批量写入）
-- 使用计数器驱动的缓冲区模式：用 head/tail 双索引指针，配合独立键存储
-- 命中事件以轻量管道分隔字符串写入，避免 JSON 编码在热路径的开销
local HIT_BUFFER_PREFIX = "waf_hit:"

function _M.record_hit(rule_id, ctx)
    local shared = ngx.shared.vn_config
    if not shared then return end

    -- 轻量序列化：管道分隔格式 (O(1) 操作，非阻塞)
    local hit_data = table.concat({
        rule_id,
        ngx.time(),
        ctx.request.uri or "",
        ctx.request.remote_addr or "",
        ctx.request.method or "GET"
    }, "|")
    local idx = shared:incr(HIT_BUFFER_PREFIX .. "tail", 1, 0)
    shared:set(HIT_BUFFER_PREFIX .. idx, hit_data)
end

-- 通过消费 head/tail 之间的所有键来刷新命中统计
-- 由 ngx.timer.every 定期调用
function _M.flush_hit_stats()
    local shared = ngx.shared.vn_config
    if not shared then return end

    -- 原子地读取并递增 head（多 worker 安全）
    local head = tonumber(shared:get(HIT_BUFFER_PREFIX .. "head") or 0)
    local tail = tonumber(shared:get(HIT_BUFFER_PREFIX .. "tail") or 0)
    if head >= tail then return end

    -- 单 worker 处理：无竞态窗口
    -- 最多每次处理 500 条，避免阻塞新请求
    local max_process = math.min(tail - head, 500)

    -- 按 rule_id 聚合命中
    local stats_agg = {}
    for i = 1, max_process do
        local key = HIT_BUFFER_PREFIX .. (head + i)
        local hit_data = shared:get(key)
        if hit_data then
            shared:delete(key)
            -- 解析管道分隔格式：rule_id|timestamp|uri|ip|method
            local rule_id, ts, uri, ip, method = hit_data:match("^([^|]*)|([^|]*)|([^|]*)|([^|]*)|([^|]*)$")
            if rule_id then
                ts = tonumber(ts)
                if not stats_agg[rule_id] then
                    stats_agg[rule_id] = { hit_count = 0, last_triggered = 0, last_matched_uri = "" }
                end
                local agg = stats_agg[rule_id]
                agg.hit_count = agg.hit_count + 1
                if ts and ts > agg.last_triggered then
                    agg.last_triggered = ts
                    agg.last_matched_uri = uri
                end
            end
        end
    end

    -- 更新 head 指针
    shared:set(HIT_BUFFER_PREFIX .. "head", head + max_process)

    -- 合并到现有统计并写回
    for rule_id, agg in pairs(stats_agg) do
        local stats_key = STATS_PREFIX .. rule_id
        local existing_json = shared:get(stats_key)
        local existing = {}
        if existing_json then
            local ok, decoded = pcall(json.decode, existing_json)
            if ok then existing = decoded end
        end

        -- 累加命中数，只保留最新的触发信息
        agg.hit_count = (existing.hit_count or 0) + agg.hit_count
        if agg.last_triggered <= (existing.last_triggered or 0) then
            agg.last_triggered = existing.last_triggered
            agg.last_matched_uri = existing.last_matched_uri
        end

        shared:set(stats_key, json.encode(agg))
    end
end

-- 初始化统计刷新定时器（init_worker 阶段调用）
function _M.init_worker()
    -- 每 30 秒刷新一次命中统计
    ngx.timer.every(30, function()
        _M.flush_hit_stats()
    end)
end

-- 速率限制检查
function _M.check_rate_limit(rule_id, rule)
    if not rule.rate_limit or not rule.rate_limit.enable then
        return true
    end

    local shared = ngx.shared.vn_config
    local key = RATE_PREFIX .. rule_id .. ":" .. math.floor(ngx.time() / (rule.rate_limit.window or 60))
    local count = shared:incr(key, 1, 1, rule.rate_limit.window or 60)

    if count and count > rule.rate_limit.max_hits then
        return false
    end
    return true
end

-- 回滚到指定版本
-- @param rule_id string: 规则 ID
-- @param target_version number: 目标版本号（整数）
function _M.rollback(rule_id, target_version)
    local history = _M.get_history(100)
    for _, record in ipairs(history) do
        if record.version == target_version then
            -- 恢复完整规则集
            if record.rule_data then
                local rules = record.rule_data
                -- 验证 rule_id 存在于恢复的规则集中
                local found = false
                for _, r in ipairs(rules) do
                    if r.id == rule_id then
                        found = true
                        break
                    end
                end
                if not found then
                    return false, "rule not found in version: " .. tostring(target_version)
                end
                return _M.save_rules(rules)
            end
        end
    end
    return false, "version not found in history"
end

-- 生成规则 ID
-- 格式: {prefix}_{timestamp}_{hex8}，使用项目统一的随机数模块
function _M.generate_id(name)
    local prefix = name:lower():match("^(%w+)") or "rule"
    local timestamp = ngx.time()
    local random_hex = require("core.random").hex(4)
    return string.format("%s_%d_%s", prefix, timestamp, random_hex)
end

-- 验证规则
function _M.validate_rule(rule)
    if not rule.name or rule.name == "" then
        return false, "name is required"
    end
    if #rule.name > 100 then
        return false, "name must be at most 100 characters"
    end
    if not rule.category or not _M.CATEGORIES[rule.category] then
        return false, "invalid category: " .. tostring(rule.category)
    end
    if not rule.severity or not _M.SEVERITY_LEVELS[rule.severity] then
        return false, "invalid severity: " .. tostring(rule.severity)
    end
    if not rule.action or not _M.ACTIONS[rule.action] then
        return false, "invalid action: " .. tostring(rule.action)
    end
    if not rule.matcher then
        return false, "matcher is required"
    end
    -- 验证 matcher 能被解析
    if type(rule.matcher) == "string" then
        local config = require("core.config")
        if not config.matcher or not config.matcher[rule.matcher] then
            return false, "matcher '" .. rule.matcher .. "' not found in config.matcher"
        end
    elseif type(rule.matcher) ~= "table" then
        return false, "matcher must be a string reference or inline table"
    end
    -- 验证 HTTP 状态码范围
    if rule.code and (type(rule.code) ~= "number" or rule.code < 200 or rule.code > 599) then
        return false, "code must be a valid HTTP status code (200-599)"
    end
    -- 验证 response 模板引用存在
    if rule.response and type(rule.response) == "string" then
        local config = require("core.config")
        if not config.response or not config.response[rule.response] then
            return false, "response template '" .. rule.response .. "' not found"
        end
    end
    -- 验证速率限制参数
    if rule.rate_limit and rule.rate_limit.enable then
        local max_hits = rule.rate_limit.max_hits
        local window = rule.rate_limit.window
        if type(max_hits) ~= "number" or max_hits < 1 or max_hits > 10000 then
            return false, "rate_limit.max_hits must be between 1 and 10000"
        end
        if type(window) ~= "number" or window < 1 or window > 3600 then
            return false, "rate_limit.window must be between 1 and 3600 seconds"
        end
        if rule.rate_limit.action and rule.rate_limit.action ~= "log" and rule.rate_limit.action ~= "block" then
            return false, "rate_limit.action must be 'log' or 'block'"
        end
    end
    return true
end

-- 常量
_M.SEVERITY_LEVELS = { critical = 1, high = 2, medium = 3, low = 4 }
_M.ACTIONS = { block = true, accept = true, log = true, challenge = true }
_M.CATEGORIES = {
    sqli = true, xss = true, rce = true, lfi = true, rfi = true,
    path_traversal = true, scanner = true, bot = true, brute = true,
    spam = true, custom = true
}

return _M
```

> **集成说明**：`waf_manager.init_worker()` 需在 `core/init.lua` 的 `init_worker_by_lua_block` 中调用：
> ```lua
> init_worker_by_lua_block {
>     local waf_manager = require("waf-rule-manager")
>     waf_manager.init_worker()
> }
> ```

### 5.2 filter/init.lua - 改造后的过滤插件

```lua
local _M = {}

_M.name = "filter"
_M.priority = 100
_M.default_enable = true
_M.critical = true

local config = require("core.config")
local matcher = require("matcher.init")
local waf_manager = require("waf-rule-manager")

function _M.on_access(ctx)
    -- 从管理器加载最新规则（带缓存）
    local rules_obj = waf_manager.load_rules()
    if not rules_obj then
        return
    end

    local rules = rules_obj.rules
    if not rules or #rules == 0 then
        return
    end

    for _, rule in ipairs(rules) do
        if rule.enable == false then
            goto continue
        end

        -- 解析匹配器
        local matcher_def = matcher.resolve(rule)
        if not matcher_def then
            goto continue
        end

        -- 测试匹配
        local matched = matcher.test(matcher_def, ctx)
        if not matched then
            goto continue
        end

        -- 速率限制检查（仅对匹配的请求生效）
        if not waf_manager.check_rate_limit(rule.id, rule) then
            goto continue
        end

        -- 记录命中统计
        waf_manager.record_hit(rule.id, ctx)

        -- 执行动作
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
        elseif rule.action == "log" then
            ngx.log(ngx.WARN, "waf: rule matched [", rule.id, "] ", rule.name, " uri=", ctx.request.uri)
        end

        ::continue::
    end
end

return _M
```

---

## 6. Dashboard UI 设计

### 6.1 页面布局

```
┌─────────────────────────────────────────────────────────────┐
│  WAF 规则管理                                    [+ 新增规则] │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────────────────────────────┐  │
│  │ 分类筛选    │  │ 规则列表                              │  │
│  │ □ SQL注入   │  │ ┌────┬──────────┬────────┬─────┬────┐│  │
│  │ □ XSS      │  │ │启用│ 规则名称 │ 分类   │命中 │操作││  │
│  │ □ RCE      │  │ ├────┼──────────┼────────┼─────┼────┤│  │
│  │ □ 扫描器   │  │ │ ✓  │ UNION... │ SQL注入│1523 │编辑││  │
│  │ □ 路径遍历 │  │ │ ✓  │ 备份文件 │ 信息泄露│ 987 │编辑││  │
│  │            │  │ │ ✗  │ Scanner  │ 扫描器 │ 456 │编辑││  │
│  │ 严重级别   │  │ └────┴──────────┴────────┴─────┴────┘│  │
│  │ □ 严重     │  │                                       │  │
│  │ □ 高危     │  │ 上一页 1 2 3 下一页  共 6 条         │  │
│  │ □ 中危     │  │                                       │  │
│  │ □ 低危     │  └──────────────────────────────────────┘  │
│  └─────────────┘                                             │
├─────────────────────────────────────────────────────────────┤
│  统计概览                                                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ 总规则数 │ │ 今日命中 │ │ 严重规则 │ │ 活跃规则 │       │
│  │    6     │ │   156    │ │    3     │    5     │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 规则编辑器

```
┌─────────────────────────────────────────────────────────────┐
│  编辑规则: SQL Injection - UNION SELECT                      │
├─────────────────────────────────────────────────────────────┤
│  规则名称*                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ SQL Injection - UNION SELECT                         │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  描述                                                       │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Detects UNION-based SQL injection in query args      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  分类*         严重级别*       优先级                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │ SQL注入 ▼│  │ 严重   ▼ │  │  100     │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
│                                                             │
│  匹配器定义                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ {                                                    │  │
│  │   "Args": {                                          │  │
│  │     "name_operator": "*",                            │  │
│  │     "operator": "≈",                                 │  │
│  │     "value": "(\\\\bunion\\\\b.+\\\\bselect\\\\b|...)" │  │
│  │   }                                                  │  │
│  │ }                                                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  动作设置                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │ 阻断   ▼ │  │  403     │  │forbidden │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
│                                                             │
│  标签                                                       │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ [sqli] [union] [injection] [+]                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  速率限制                                                    │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ ☑ 启用    最大命中: 10    窗口(秒): 60    动作: 日志 │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  [测试规则]  [保存]  [取消]                                  │
└─────────────────────────────────────────────────────────────┘
```

### 6.3 测试工具

```
┌─────────────────────────────────────────────────────────────┐
│  规则测试: SQL Injection - UNION SELECT                      │
├─────────────────────────────────────────────────────────────┤
│  测试用例                                                    │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 用例1: 正常请求                                       │  │
│  │ URI: /api/users                                       │  │
│  │ 预期: 不匹配 ✓                                        │  │
│  │ 结果: 不匹配 ✓                                        │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │ 用例2: SQL注入                                        │  │
│  │ URI: /api/users?id=1 UNION SELECT * FROM users--     │  │
│  │ 预期: 匹配 ✓                                          │  │
│  │ 结果: 匹配 ✓                                          │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │ 用例3: 编码绕过                                       │  │
│  │ URI: /api/users?id=1%20UNION%20SELECT                │  │
│  │ 预期: 匹配 ✓                                          │  │
│  │ 结果: 匹配 ✓                                          │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  测试结果: 3/3 通过  ✓                                      │
│                                                             │
│  [添加用例]  [重新测试]                                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. 安全考虑

### 7.1 访问控制

- 所有 WAF 管理 API 需要 `auth_required = true`
- 仅 admin 角色可访问
- 操作记录到 audit log

### 7.2 规则验证

- 规则名称必填，长度 1-100 字符
- 分类必须是预定义分类之一
- 严重级别必须是 critical/high/medium/low 之一
- 动作必须是 block/accept/log/challenge 之一
- 匹配器定义必须能被 `matcher.resolve()` 解析
- 速率限制参数必须为正整数

### 7.3 防误操作

- 删除规则需要二次确认
- 规则修改自动创建版本记录
- 支持一键回滚
- 默认规则不可删除（可禁用）

### 7.4 性能保护

- 规则缓存使用 shared dict 分片存储（每 100 条规则一个 chunk），避免单 key 超限
- 规则数量上限 1000 条
- 单条规则匹配超时 10ms
- 统计更新使用 `ngx.timer.every` 异步批量写入

---

## 8. 实施计划

### 阶段一：核心功能（2 天）

| 任务 | 文件 | 预计时间 |
|------|------|----------|
| 创建 waf-rule-manager.lua | verynginx/waf-rule-manager.lua | 4h |
| 改造 filter/init.lua | verynginx/plugin/filter/init.lua | 2h |
| 新增 API 路由 | verynginx/api/init.lua | 4h |
| 更新 config schema | verynginx/core/config.lua | 2h |
| 单元测试 | test/v2/spec/waf_rule_manager_spec.lua | 4h |

### 阶段二：管理界面（2 天）

| 任务 | 文件 | 预计时间 |
|------|------|----------|
| Dashboard WAF 页面 | verynginx/dashboard/index.html | 8h |
| 规则编辑器组件 | verynginx/dashboard/js/waf-editor.js | 4h |
| 测试工具组件 | verynginx/dashboard/js/waf-tester.js | 4h |

### 阶段三：高级功能（1 天）

| 任务 | 文件 | 预计时间 |
|------|------|----------|
| 版本历史 API | verynginx/api/init.lua | 2h |
| 回滚 API | verynginx/api/init.lua | 2h |
| 统计 API | verynginx/api/init.lua | 2h |
| 集成测试 | test/v2/test_integration.py | 2h |

### 阶段四：迁移与文档（1 天）

| 任务 | 文件 | 预计时间 |
|------|------|----------|
| 迁移现有规则 | verynginx/plugin/filter/rules.lua | 2h |
| API 文档 | docs/WAF_API.md | 2h |
| 用户指南 | docs/WAF_GUIDE.md | 2h |

---

## 9. 迁移策略

### 从硬编码到可配置

**步骤 1**：将现有 `filter/rules.lua` 中的规则迁移到 `config.json`

```lua
-- 迁移脚本 (一次性)
-- 注意：config 模块有只读元表，不能直接设置字段。
-- 需构建完整配置对象后调用 config.save()。
local rules = require("plugin.filter.rules")
local config = require("core.config")

local waf_rules = {
    version = 1,
    timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    rules = {}
}

-- 转换默认规则
for _, rule in ipairs(rules.default_rules) do
    table.insert(waf_rules.rules, {
        id = rule.matcher .. "_default",
        name = rule.matcher:gsub("_", " "):gsub("^%l", string.upper),
        description = "Built-in rule for " .. rule.matcher,
        category = rule.matcher:match("^attack_(.+)$") or "custom",
        severity = rule.action == "block" and "critical" or "medium",
        enable = rule.enable,
        matcher = rule.matcher,
        action = rule.action,
        code = rule.code,
        response = rule.response,
        tags = { rule.matcher },
        created_at = "2026-06-28T12:00:00Z"
    })
end

-- 构建完整配置对象（复制现有字段 + 添加 waf_rules）
local new_config = {}
for k, v in pairs(config.schema.fields) do
    new_config[k] = config[k]
end
new_config.waf_rules = waf_rules

-- 保存（config.save 会写入内部 config_data 表）
local ok, err = config.save(new_config)
if not ok then
    print("Migration failed: " .. tostring(err))
else
    print("Migration success: " .. #waf_rules.rules .. " rules migrated")
end
```

**步骤 2**：保留 `filter/rules.lua` 作为 fallback

```lua
local _M = {}

-- 默认规则（fallback，当 config 无规则时使用）
_M.default_rules = {
    -- ... 保留现有规则作为 fallback
}

-- 加载规则：优先 config，fallback 默认
function _M.load_rules()
    local config = require("core.config")
    if config.waf_rules and config.waf_rules.rules then
        return config.waf_rules.rules
    end
    return _M.default_rules
end

return _M
```

**步骤 3**：渐进式迁移

1. 第一阶段：新规则通过 API 添加，旧规则保持不变
2. 第二阶段：旧规则逐步迁移到 config.json
3. 第三阶段：移除硬编码的默认规则（保留 fallback）

---

## 10. 总结

### 设计亮点

1. **双层存储**：shared dict 缓存 + JSON 文件持久化，兼顾性能与可靠性
2. **原子写入**：tmp + rename 保证数据一致性
3. **版本控制**：每次变更自动记录，支持任意版本回滚
4. **规则测试**：上线前可验证规则正确性，减少误报
5. **丰富元数据**：分类、严重级别、标签、统计信息
6. **条件组合**：支持 AND/OR 逻辑组合多个条件
7. **速率限制**：每条规则可独立配置速率限制
8. **Dashboard 集成**：可视化管理界面

### 与现有架构的兼容性

- 复用现有 matcher 体系，无需重写匹配逻辑
- 复用现有 config 系统，规则保存在 config.json
- 复用现有 auth/audit 系统，权限控制一致
- 复用现有备份/回滚机制，规则版本与配置版本统一管理

### 预期效果

- 规则维护从"改代码+重启"变为"Web 界面点击"
- 规则变更有记录、可追溯、可回滚
- 新规则上线前可测试，减少误报
- 运行时统计帮助识别高频攻击

---

## 附录

### A. 默认规则迁移对照表

| 原硬编码规则 | 新规则 ID | 分类 | 严重级别 |
|-------------|----------|------|----------|
| attack_sqli | sqli_default | sqli | critical |
| attack_backup | backup_default | path_traversal | high |
| attack_scanner | scanner_default | scanner | medium |
| attack_code_leak | code_leak_default | lfi | high |
| attack_path_traversal | path_traversal_default | path_traversal | critical |
| attack_rce | rce_default | rce | critical |

### B. API 端点速查

| 方法 | 路径 | 说明 | 需要认证 |
|------|------|------|----------|
| GET | /waf/rules | 获取所有规则 | ✅ |
| POST | /waf/rules | 创建新规则 | ✅ |
| GET | /waf/rules/:id | 获取单条规则 | ✅ |
| PUT | /waf/rules/:id | 更新规则 | ✅ |
| DELETE | /waf/rules/:id | 删除规则 | ✅ |
| POST | /waf/rules/:id/enable | 启用规则 | ✅ |
| POST | /waf/rules/:id/disable | 禁用规则 | ✅ |
| POST | /waf/rules/test | 测试规则 | ✅ |
| POST | /waf/rules/reload | 热重载规则 | ✅ |
| GET | /waf/rules/history | 获取变更历史 | ✅ |
| POST | /waf/rules/rollback | 回滚到指定版本 | ✅ |
| GET | /waf/stats | 获取统计信息 | ✅ |
| GET | /waf/stats/:id | 获取单条规则统计 | ✅ |

### C. 文件变更清单

| 文件 | 操作 | 说明 |
|------|------|------|
| verynginx/waf-rule-manager.lua | 新增 | 规则管理器核心模块 |
| verynginx/plugin/filter/init.lua | 修改 | 改为从管理器加载规则 |
| verynginx/plugin/filter/rules.lua | 修改 | 保留为 fallback |
| verynginx/api/init.lua | 修改 | 新增 WAF 管理 API |
| verynginx/core/config.lua | 修改 | 新增 waf_rules schema |
| verynginx/dashboard/index.html | 修改 | 新增 WAF 管理页面 |
| test/v2/spec/waf_rule_manager_spec.lua | 新增 | 规则管理器单元测试 |
| test/v2/test_integration.py | 修改 | 新增 WAF API 集成测试 |
