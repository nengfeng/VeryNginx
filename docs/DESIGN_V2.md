# VeryNginx v2.0 架构设计方案

> v2.0 作为全新架构设计，不承担 v1.x 配置或 API 兼容目标。核心目标：**关注点分离、无副作用匹配、可扩展插件化、安全默认值、高性能热更新、可观测可测试**。

---

## 一、问题回顾

v1.x 的主要设计缺陷：

| # | 问题 | 根因 |
|---|------|------|
| 1 | 每个请求读配置文件 | 热更新检测依赖文件 I/O |
| 2 | Matcher 有副作用（读 body） | 匹配与数据获取耦合 |
| 3 | 访问阶段无短路 | 模块硬编码顺序执行 |
| 4 | 全局可变状态 | 配置直接暴露为全局表 |
| 5 | `ngx.exec` 滥用 | 内部重定向作为 workaround |
| 6 | 模块职责不清 | 配置/路由/认证/统计混在一起 |
| 7 | 配置变更脆弱 | 字符串键 + 无回滚 + 无编译期校验 |
| 8 | 无模块注册机制 | 扩展需改核心代码 |
| 9 | 统计精度问题 | 多 key 无事务性 |
| 10 | 认证耦合 | 认证逻辑写在路由模块里 |

---

## 二、总体架构

```
┌─────────────────────────────────────────────────────────────┐
│                        Nginx 核心                           │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────────┐
│  init_by_lua │    │ rewrite_by   │    │   access_by_lua  │
│              │    │    lua       │    │                  │
│  插件注册    │    │  配置热更新  │    │  规则引擎执行    │
│  共享内存    │    │  URI 重写    │    │  (带短路优化)    │
│  worker初始化│    │  Scheme锁    │    │                  │
└──────────────┘    └──────────────┘    └──────────────────┘
                                                │
                              ┌─────────────────┼─────────────────┐
                              ▼                 ▼                 ▼
                        ┌──────────┐     ┌──────────┐     ┌──────────┐
                        │  Filter  │     │  Backend │     │  Router  │
                        │  Engine  │     │  Engine  │     │  Engine  │
                        └──────────┘     └──────────┘     └──────────┘
                              │                 │                 │
                              ▼                 ▼                 ▼
                        ┌──────────┐     ┌──────────┐     ┌──────────┐
                        │  Matcher │     │  Balancer│     │  Auth    │
                        │  System  │     │  System  │     │  System  │
                        └──────────┘     └──────────┘     └──────────┘
                              │
                              ▼
                        ┌──────────┐
                        │ Statistics│
                        │  Engine   │
                        └──────────┘
```

---

## 三、目录结构

```
verynginx/
├── core/                          # 核心框架
│   ├── init.lua                   # 初始化入口（插件注册、共享内存、worker 定时器）
│   ├── config.lua                 # 配置管理（加载/保存/热更新/回滚）
│   ├── context.lua                # 请求上下文（ngx.ctx 封装，统一数据传递）
│   ├── plugin.lua                 # 插件注册中心
│   ├── rule_engine.lua            # 规则引擎（匹配+决策+动作应用）
│   ├── statistics.lua             # 统计引擎（统一计数、定时聚合、持久化）
│   ├── metrics.lua                # Prometheus 指标封装（counter/histogram/gauge）
│   ├── session.lua                # HMAC session 签名、验证、过期
│   ├── password_hash.lua          # 管理员密码哈希与校验
│   ├── random.lua                 # 安全随机数封装
│   └── observability.lua          # metrics、trace、插件耗时、健康状态
│
├── matcher/                       # 匹配器（纯函数，无副作用）
│   ├── init.lua                   # 匹配器注册中心
│   ├── uri.lua                    # URI 匹配
│   ├── ip.lua                     # IP 匹配
│   ├── ua.lua                     # UserAgent 匹配
│   ├── host.lua                   # Host 匹配
│   ├── referer.lua                # Referer 匹配
│   ├── args.lua                   # 参数匹配（延迟读取 body）
│   ├── header.lua                 # Header 匹配
│   ├── cookie.lua                 # Cookie 匹配
│   ├── method.lua                 # Method 匹配
│   └── composite.lua              # 组合匹配器（AND/OR/NOT）
│
├── action/                        # 动作执行器
│   ├── init.lua                   # 动作注册中心
│   ├── accept.lua                 # 放行
│   ├── block.lua                  # 拦截（可返回自定义响应）
│   ├── redirect.lua               # 重定向
│   ├── rewrite.lua                # URI 重写
│   ├── scheme_lock.lua            # Scheme 锁定
│   └── response.lua               # 自定义响应体
│
├── plugin/                        # 功能插件（可独立启用/禁用）
│   ├── filter/                    # WAF 防火墙
│   │   ├── init.lua               # 插件入口
│   │   ├── rules.lua              # 默认规则集
│   │   └── matcher.lua           # 匹配逻辑
│   ├── frequency_limit/           # 频率限制
│   │   ├── init.lua
│   │   └── limiter.lua
│   ├── browser_verify/            # 浏览器验证
│   │   ├── init.lua
│   │   ├── cookie_verify.lua
│   │   └── javascript_verify.lua
│   ├── router/                    # 管理路径路由和 API 分发
│   │   └── init.lua
│   ├── proxy_pass/                # 反向代理
│   │   ├── init.lua
│   │   ├── balancer.lua           # 动态负载均衡（balancer_by_lua）
│   │   ├── health_check.lua       # 主动/被动健康检查
│   │   └── dns_cache.lua          # DNS 缓存（A/AAAA，TTL，stale-if-error）
│   ├── static_file/               # 静态文件服务
│   │   └── init.lua
│   └── summary/                   # 请求统计
│       ├── init.lua
│       ├── collector.lua
│       └── reporter.lua
│
├── api/                           # API 层（管理面板后端）
│   ├── init.lua                   # API 路由注册
│   ├── auth.lua                   # 认证中间件
│   ├── csrf.lua                   # CSRF 校验
│   ├── rate_limit.lua             # 管理接口限流
│   ├── config_controller.lua      # 配置 CRUD
│   ├── status_controller.lua      # 状态查询
│   ├── metrics_controller.lua     # Prometheus metrics
│   └── summary_controller.lua     # 统计查询
│
├── dashboard/                     # 管理面板前端（SPA，单文件）
│   └── index.html                 # Vue 3 单页应用（含全部 CSS/JS）
│
├── nginx_conf/                    # Nginx 配置片段
│   ├── in_external.conf
│   ├── in_http_block.conf
│   └── in_server_block.conf
│
├── support/
│   └── verify_javascript.html
│
└── configs/                       # 运行时配置和持久化数据
    ├── config.json
    ├── backups/
    └── statistics.json
```

---

## 四、核心模块详细设计

### 4.1 配置管理 (`core/config.lua`)

**设计目标**：热更新零 I/O、原子性变更、可回滚、并发保存安全。

```lua
local _M = {}
local metrics = require "core.metrics"

-- 配置 schema 定义（用于默认值、验证、编译）
_M.schema = {
    version = "2.0",
    fields = {
        base_uri = { type = "string", default = "/verynginx" },
        dashboard_host = { type = "string", default = "" },
        cookie_prefix = { type = "string", default = "verynginx" },
        admin = { type = "table", default = {} },
        matcher = { type = "table", default = {} },
        rule = { type = "table", default = {} },
        backend_upstream = { type = "table", default = {} },
        response = { type = "table", default = {} },
        plugin = { type = "table", default = {} },
        security = { type = "table", default = {} },
        statistics = { type = "table", default = {} },
        observability = { type = "table", default = {} },
        body = { type = "table", default = { max_size = 1048576 } },
        proxy = { type = "table", default = { health_check_interval = 5 } },
        config_save_lock_ttl = { type = "number", default = 60 },
    }
}

-- 配置存储：内存中只保留一个不可变快照
local config_store = {}
local config_mt = {
    __index = function(t, k)
        return config_store[k]
    end,
    __newindex = function(t, k, v)
        error("config is readonly, use config.save()")
    end
}
setmetatable(_M, config_mt)

-- 热更新：仅比较 shared dict 中的 hash，不读文件
function _M.check_update()
    local shared = ngx.shared.vn_config
    local remote_hash = shared:get('config_hash')
    if remote_hash and remote_hash ~= _M.local_hash then
        -- 双重检查：保存锁存在时不读取文件，避免读到非预期中间状态
        if shared:get("config_save_lock") then
            return
        end
        _M.load_from_file()
    end
end

-- 加载配置：仅在启动或 hash 变化时调用
function _M.load_from_file()
    local path = _M.config_path .. "/configs/config.json"
    local file = io.open(path, "r")
    if not file then return false end

    local data = file:read("*all")
    file:close()

    local new_hash = ngx.md5(data)
    local config = json.decode(data)

    if not config then
        ngx.log(ngx.ERR, "config.json decode error")
        return false
    end

    -- 验证配置
    local valid, normalized_or_err, compiled = _M.validate_and_compile(config)
    if not valid then
        ngx.log(ngx.ERR, "config validation failed: ", normalized_or_err)
        return false
    end

    -- 原子性替换
    config_store = readonly(compiled)
    _M.local_hash = new_hash

    -- 更新 shared dict hash（触发其他 worker 更新）
    local shared = ngx.shared.vn_config
    shared:set('config_hash', new_hash)

    return true
end

-- 保存配置：验证 + 备份 + 原子写入 + 激活
function _M.save(config)
    local shared = ngx.shared.vn_config
    local lock_key = "config_save_lock"
    local lock_ttl = config.config_save_lock_ttl or 60
    local lock_token = random.bytes(16)

    -- shared dict add 是原子操作，用于避免并发保存互相覆盖
    local locked = shared:add(lock_key, lock_token, lock_ttl)
    if not locked then
        return false, "config save is already running"
    end

    -- 验证并编译
    local valid, normalized_or_err, compiled = _M.validate_and_compile(config)
    if not valid then
        _M.release_save_lock(lock_key, lock_token)
        return false, normalized_or_err
    end

    -- 文件中只保存规范化后的纯 JSON 配置，编译产物只存在内存快照
    local encoded = json.encode(normalized_or_err, { indent = true })
    local new_hash = ngx.md5(encoded)
    local tmp_path = _M.config_path .. "/configs/config.json.tmp"
    local final_path = _M.config_path .. "/configs/config.json"
    local backup_path = _M.make_backup(final_path)
    _M.refresh_save_lock(lock_key, lock_token, lock_ttl)

    -- 写入临时文件，再原子性重命名
    local file = io.open(tmp_path, "w")
    if not file then
        _M.release_save_lock(lock_key, lock_token)
        return false, "cannot open temp file"
    end

    file:write(encoded)
    file:close()
    _M.refresh_save_lock(lock_key, lock_token, lock_ttl)

    local ok, err = os.rename(tmp_path, final_path)
    if not ok then
        _M.release_save_lock(lock_key, lock_token)
        return false, err
    end

    -- 当前 worker 立即激活，其他 worker 通过 hash 感知更新
    config_store = readonly(compiled)
    _M.local_hash = new_hash
    shared:set("config_backup_latest", backup_path)
    shared:set('config_hash', new_hash)
    _M.release_save_lock(lock_key, lock_token)

    return true
end

function _M.refresh_save_lock(lock_key, lock_token, lock_ttl)
    local shared = ngx.shared.vn_config
    if shared:get(lock_key) == lock_token then
        shared:expire(lock_key, lock_ttl)
    end
end

function _M.release_save_lock(lock_key, lock_token)
    local shared = ngx.shared.vn_config
    if shared:get(lock_key) == lock_token then
        shared:delete(lock_key)
    end
end

function _M.make_backup(final_path)
    -- 保存前复制当前 config.json 到 configs/backups/config.<timestamp>.json
    -- 保留最近 config.backup_keep 或 10 份
    local backup_path = _M.config_path .. "/configs/backups/config." .. ngx.time() .. ".json"
    copy_file(final_path, backup_path)
    prune_backups(config.backup_keep or 10)
    return backup_path
end

-- 回滚：从备份恢复并重新激活
function _M.rollback(backup_path)
    local file = io.open(backup_path, "r")
    if not file then
        return false, "backup not found"
    end
    local data = file:read("*all")
    file:close()
    local config = json.decode(data)
    if not config then
        return false, "backup decode failed"
    end
    return _M.save(config)
end

-- 配置验证与编译
function _M.validate_and_compile(config)
    -- 检查必填字段
    -- 检查类型
    -- 检查规则引用完整性
    -- 编译 matcher、regex、插件优先级、upstream 健康检查参数
    -- 拒绝未知 matcher/action/plugin，避免 fail-open
    local normalized = normalize_defaults(config, _M.schema)
    local compiled = compile_runtime_snapshot(normalized)
    return true, normalized, compiled
end

return _M
```

**关键改进**：
- 热更新检测只比较 `shared dict` 中的 hash，**零文件 I/O**
- 配置以不可变快照形式暴露，插件不能直接修改运行时配置
- 配置保存使用带 token 的 shared dict 锁，默认 TTL 60 秒，并在关键 I/O 步骤续期
- 文件写入使用 `tmp + rename` 原子操作，保存前保留最近 N 个备份
- 配置加载阶段完成 schema 校验、引用完整性校验、matcher/action/plugin 编译

---

### 4.2 请求上下文 (`core/context.lua`)

**设计目标**：统一数据传递，避免 `ngx.ctx` 的隐式依赖。

```lua
local _M = {}

-- 每个请求的上下文对象
function _M.new()
    return {
        -- 请求信息（只读）
        request = {
            uri = ngx.var.uri,
            method = ngx.req.get_method(),
            remote_addr = ngx.var.remote_addr,
            host = ngx.var.host,
            user_agent = ngx.var.http_user_agent,
            referer = ngx.var.http_referer,
            scheme = ngx.var.scheme,
            trace_id = ngx.var.request_id or ngx.var.connection .. "-" .. ngx.var.connection_requests,
            -- body 延迟读取
            _body_args = nil,
            _body_read = false,
            _body_error = nil,
        },

        -- 匹配结果缓存（单请求内有上限）
        match_cache = {},
        match_cache_size = 0,

        -- 动作执行结果
        action_result = nil,

        -- 统计数据引用
        stat_ref = nil,

        -- 插件间通信数据，key 使用 plugin_name:field 命名空间
        data = {},

        -- 显式方法引用，避免各模块直接依赖 core.context 模块
        get_body_args = _M.get_body_args,
        get_uri_args = _M.get_uri_args,
        set_action = _M.set_action,
        has_decision = _M.has_decision,
        clear_action = _M.clear_action,
        set_data = _M.set_data,
        get_data = _M.get_data,
    }
end

-- 延迟读取 body（仅在需要时）
function _M.get_body_args(ctx)
    if ctx.request._body_read then
        return ctx.request._body_args
    end

    local max_size = config.body.max_size or 1048576
    local content_length = tonumber(ngx.var.content_length) or 0
    if content_length > max_size then
        ctx.request._body_error = "body_too_large"
        ctx.request._body_read = true
        return nil
    end

    ngx.req.read_body()

    -- 如果 body 被缓存到文件，按配置决定拒绝或跳过 body 参数匹配
    if ngx.req.get_body_file() then
        ctx.request._body_error = "body_buffered_to_file"
        ctx.request._body_args = nil
        ctx.request._body_read = true
        return nil
    end

    local args, err = ngx.req.get_post_args(config.body.max_args or 100)
    if err then
        ctx.request._body_error = err
    end
    ctx.request._body_args = args
    ctx.request._body_read = true
    return args
end

-- 获取 URI 参数（不读 body）
function _M.get_uri_args(ctx)
    return ngx.req.get_uri_args()
end

-- 设置动作执行结果
function _M.set_action(ctx, action_type, data)
    ctx.action_result = {
        type = action_type,
        data = data
    }
end

-- 检查是否已有决策
function _M.has_decision(ctx)
    return ctx.action_result ~= nil
end

function _M.clear_action(ctx)
    ctx.action_result = nil
end

-- 插件间通信
function _M.set_data(ctx, key, value)
    ctx.data[key] = value
end

function _M.get_data(ctx, key)
    return ctx.data[key]
end

return _M
```

**关键改进**：
- Body 延迟读取，只在真正需要时才读
- Body 读取受 `config.body.max_size` 和 `max_args` 限制，避免大请求体 DoS
- 匹配结果缓存有上限，避免单请求内异常增长
- 统一的决策检查，支持短路
- `ctx.data` 提供标准化插件间通信，避免插件互相读取私有状态
- `trace_id` 贯穿日志、统计、代理请求头和错误排查

---

### 4.3 匹配器系统 (`matcher/`)

**设计目标**：纯函数、无副作用、可组合。

```lua
-- matcher/init.lua
local _M = {}

-- 匹配器注册表
_M.registry = {}

-- 注册匹配器
function _M.register(name, handler)
    _M.registry[name] = handler
end

-- 执行匹配（纯函数：ctx → bool）
function _M.test(matcher_def, ctx)
    if not matcher_def or next(matcher_def) == nil then
        return true  -- 空匹配器匹配所有
    end

    -- 检查缓存
    local cache_key = ngx.crc32_short(json.encode(matcher_def))
    if ctx.match_cache[cache_key] ~= nil then
        return ctx.match_cache[cache_key]
    end

    local result = true

    for condition_type, condition in pairs(matcher_def) do
        local handler = _M.registry[condition_type]
        if handler then
            local ok = handler(condition, ctx)
            if not ok then
                result = false
                break  -- AND 关系，任一不匹配则失败
            end
        else
            return false  -- 配置加载阶段会拒绝未知 matcher，运行期兜底 fail-closed
        end
    end

    -- 缓存结果
    if ctx.match_cache_size < (config.matcher_cache_size or 128) then
        ctx.match_cache[cache_key] = result
        ctx.match_cache_size = ctx.match_cache_size + 1
    end
    return result
end

return _M
```

```lua
-- matcher/uri.lua
local _M = {}

function _M.test(condition, ctx)
    local uri = ctx.request.uri
    local operator = condition.operator
    local value = condition.value

    if operator == "=" then
        return uri == value
    elseif operator == "≈" then
        return ngx.re.find(uri, value, "isjo") ~= nil
    elseif operator == "!≈" then
        return ngx.re.find(uri, value, "isjo") == nil
    elseif operator == "*" then
        return true
    end

    return false
end

return _M
```

```lua
-- matcher/args.lua
local _M = {}

function _M.test(condition, ctx)
    local name_operator = condition.name_operator
    local name_value = condition.name_value
    local operator = condition.operator
    local value = condition.value

    -- 先检查 URI 参数（不读 body）
    local uri_args = ctx.get_uri_args(ctx)
    if _M._test_args(uri_args, name_operator, name_value, operator, value) then
        return true
    end

    -- 再检查 body 参数（延迟读取）
    local body_args = ctx.get_body_args(ctx)
    if body_args then
        return _M._test_args(body_args, name_operator, name_value, operator, value)
    end
    if ctx.request._body_error then
        local policy = condition.on_body_error or config.body.on_error or "skip"
        return policy == "match" or policy == "fail_closed"
    end

    return false
end

function _M._test_args(args, name_op, name_val, op, val)
    for k, v in pairs(args) do
        if _M._match_var(name_op, name_val, k) then
            if type(v) == "table" then
                for _, arg_val in ipairs(v) do
                    if _M._match_var(op, val, arg_val) then
                        return true
                    end
                end
            else
                if _M._match_var(op, val, v) then
                    return true
                end
            end
        end
    end
    return false
end

function _M._match_var(operator, pattern, target)
    if operator == "=" then
        return target == pattern
    elseif operator == "≈" then
        return type(target) == "string" and ngx.re.find(target, pattern, "isjo") ~= nil
    elseif operator == "!≈" then
        return type(target) ~= "string" or ngx.re.find(target, pattern, "isjo") == nil
    elseif operator == "*" then
        return true
    end
    return false
end

return _M
```

**关键改进**：
- 匹配器是纯函数，只依赖 `ctx` 输入
- Body 读取延迟到真正需要时
- 匹配结果缓存限制在单请求固定上限内，避免异常增长
- 未知 matcher/action 在配置加载阶段拒绝，运行时兜底 fail-closed
- 组合 matcher 明确定义 AND/OR/NOT 语义，复杂条件不依赖 Lua `pairs()` 顺序
- 正则在配置加载阶段预编译或验证，运行期只执行匹配
- `matcher/cookie.lua` 只负责 Cookie 条件匹配，`api/auth.lua` 的 session 模块只负责认证会话，二者不共享状态

**`Args` matcher 的 `on_body_error` 语义**：
- 可选值：`"match"`、`"skip"`、`"fail_closed"`
- 优先级：`condition.on_body_error` > `config.body.on_error` > 默认 `"skip"`
- `"match"` 表示 body 读取失败时该条件视为匹配，通常配合 block 规则使用
- `"skip"` 表示跳过 body 参数匹配，只保留 URI 参数匹配结果
- `"fail_closed"` 表示按匹配处理，让 WAF/限流等规则可以拒绝请求
- 配置保存阶段必须拒绝其他取值

---

### 4.4 规则引擎 (`core/rule_engine.lua`)

**设计目标**：带短路优化的规则执行。

```lua
local _M = {}

-- 规则执行结果
local RESULT = {
    PASS = "pass",       -- 继续执行
    ACCEPT = "accept",   -- 放行请求
    BLOCK = "block",     -- 拦截请求
    REWRITE = "rewrite", -- URI 重写
    REDIRECT = "redirect",-- 重定向
    RESPONSE = "response",-- 自定义响应
    PROXY = "proxy",     -- 反向代理
    STATIC = "static",   -- 静态文件
}

-- 执行规则链（带短路）
function _M.execute(rules, ctx)
    for _, rule in ipairs(rules) do
        if not rule.enable then
            goto continue
        end

        -- 匹配检查
        local matched = matcher.test(rule.matcher, ctx)

        if matched then
            local action = rule.action
            local action_handler = action_registry[action]

            if action_handler then
                local result = action_handler(rule, ctx)

                if result.type ~= RESULT.PASS then
                    -- 做出决策，短路返回
                    ctx.set_action(ctx, result.type, result.data)
                    return result
                end
            end
        end

        ::continue::
    end

    return { type = RESULT.PASS }
end

-- 应用动作：把规则决策转换为 Nginx 行为
function _M.apply(ctx, phase)
    local action = ctx.action_result
    if not action then
        return
    end

    if action.type == RESULT.BLOCK then
        local resp = response.resolve(action.data.response)
        ngx.status = action.data.code or resp.code or 403
        ngx.header["Content-Type"] = resp.content_type or "text/plain"
        ngx.say(resp.body or "Forbidden")
        return ngx.exit(ngx.status)
    elseif action.type == RESULT.REDIRECT then
        return ngx.redirect(action.data.url, action.data.code or 302)
    elseif action.type == RESULT.RESPONSE then
        local resp = response.resolve(action.data.response)
        ngx.status = action.data.code or resp.code or 200
        ngx.header["Content-Type"] = resp.content_type or "text/plain"
        ngx.say(resp.body or "")
        return ngx.exit(ngx.status)
    elseif action.type == RESULT.REWRITE and phase == "rewrite" then
        ngx.req.set_uri(action.data.uri, false)
        ctx.clear_action(ctx)
        return
    elseif action.type == RESULT.PROXY then
        ngx.var.vn_proxy_scheme = action.data.scheme
        ngx.var.vn_proxy_host = action.data.host
        ngx.var.vn_proxy_port = action.data.port
        ngx.var.vn_proxy_sni = action.data.sni or action.data.host
    elseif action.type == RESULT.STATIC then
        return static_file.serve(action.data.root, action.data.path, action.data.expires)
    elseif action.type == RESULT.ACCEPT then
        return
    end
end

return _M
```

**关键改进**：
- 规则引擎只负责产生决策，`apply()` 统一负责落地到 Nginx 行为
- `block/redirect` 是终止动作，必须立即 `ngx.exit` 或 `ngx.redirect`
- `response` 是独立终止动作，用于返回非拦截类自定义响应
- `rewrite` 只允许在 rewrite 阶段生效，避免 access 阶段修改 URI 带来不可预测行为
- `proxy` 只设置受控变量，`static` 通过 `static_file.serve` 受控输出文件，不再把 `ngx.exec` 当作业务控制流

---

#### `response.resolve()` 语义 (`action/response.lua`)

```lua
local _M = {}

function _M.resolve(response_def)
    if type(response_def) == "string" then
        local template = config.response[response_def]
        if not template then
            return { code = 500, content_type = "text/plain", body = "response template not found" }
        end
        return template
    end

    if type(response_def) == "table" then
        return {
            code = response_def.code,
            content_type = response_def.content_type or "text/plain",
            body = response_def.body or ""
        }
    end

    return { code = 403, content_type = "text/plain", body = "Forbidden" }
end

return _M
```

**关键要求**：
- 字符串表示模板名称，例如 `"forbidden_json"`，必须从 `config.response` 查找
- table 表示内联响应对象，例如 `{ code = 403, body = "..." }`
- 配置保存阶段必须验证所有模板引用存在，运行期找不到模板只作为兜底错误
- `block` action 和独立 `response` action 都必须复用该函数

---

### 4.5 插件系统 (`core/plugin.lua`)

**设计目标**：可插拔、可配置执行顺序、关键插件 fail-closed。

```lua
local _M = {}

-- 插件注册表
_M.plugins = {}

-- 插件接口定义
--[[
    plugin = {
        name = "filter",           -- 插件名称
        priority = 100,            -- 执行优先级（越小越先执行）
        default_enable = true,      -- 默认是否启用
        critical = true,            -- 崩溃时是否拒绝请求
        fail_code = 503,            -- fail-closed 响应码

        -- 生命周期钩子
        on_init = function() end,  -- 初始化时调用
        on_access = function(ctx) end,  -- 访问阶段调用
        on_log = function(ctx) end,    -- 日志阶段调用
    }
--]]

-- 注册插件
function _M.register(plugin)
    table.insert(_M.plugins, plugin)
    table.sort(_M.plugins, function(a, b)
        local ap = (config.plugin[a.name] and config.plugin[a.name].priority) or a.priority
        local bp = (config.plugin[b.name] and config.plugin[b.name].priority) or b.priority
        return ap < bp
    end)
end

function _M.is_enabled(plugin)
    local conf = config.plugin[plugin.name] or {}
    if conf.enable == nil then
        return plugin.default_enable ~= false
    end
    return conf.enable == true
end

function _M.handle_error(plugin, ctx, phase, err)
    ngx.log(ngx.ERR, "plugin ", phase, " failed: ", plugin.name, " - ", err)
    metrics.incr("plugin_errors_total", 1, { plugin = plugin.name, phase = phase })
    local conf = config.plugin[plugin.name] or {}
    local critical = conf.critical
    if critical == nil then
        critical = plugin.critical
    end
    if critical then
        ctx.set_action(ctx, "block", {
            code = plugin.fail_code or 503,
            response = "Service Unavailable"
        })
    end
end

-- 初始化所有插件
function _M.init_all()
    for _, plugin in ipairs(_M.plugins) do
        if _M.is_enabled(plugin) and plugin.on_init then
            local ok, err = pcall(plugin.on_init)
            if not ok then
                ngx.log(ngx.ERR, "plugin init failed: ", plugin.name, " - ", err)
            end
        end
    end
end

-- 执行访问阶段
function _M.execute_access(ctx)
    for _, plugin in ipairs(_M.plugins) do
        if not _M.is_enabled(plugin) then
            goto continue
        end

        -- 检查是否已有决策（短路）
        if ctx.has_decision(ctx) then
            break
        end

        if plugin.on_access then
            local ok, err = pcall(plugin.on_access, ctx)
            if not ok then
                _M.handle_error(plugin, ctx, "access", err)
            end
        end

        ::continue::
    end
end

-- 执行日志阶段
function _M.execute_log(ctx)
    for _, plugin in ipairs(_M.plugins) do
        if _M.is_enabled(plugin) and plugin.on_log then
            local ok, err = pcall(plugin.on_log, ctx)
            if not ok then
                ngx.log(ngx.ERR, "plugin log failed: ", plugin.name, " - ", err)
            end
        end
    end
end

return _M
```

**关键改进**：
- 插件启停、优先级、critical 策略统一来自 `config.plugin`
- WAF、限流、认证类关键插件默认 fail-closed，统计、日志类插件可 fail-open
- 插件间只通过 `ctx.data` 通信，禁止读取其他插件私有字段
- 插件初始化失败必须暴露到健康状态，不能只写错误日志

---

### 4.6 统计引擎 (`core/statistics.lua`)

**设计目标**：减少写入次数、支持时间窗口、限制基数、支持持久化和指标导出。

```lua
local _M = {}

-- 统计桶：按时间窗口聚合
local STAT_BUCKETS = {
    "1m",   -- 1 分钟
    "5m",   -- 5 分钟
    "1h",   -- 1 小时
    "all",  -- 累计
}

-- 初始化
function _M.init()
    -- 该函数必须从 init_worker_by_lua 调用
    ngx.timer.every(60, function()
        _M._flush_bucket("1m", "5m")
    end)

    ngx.timer.every(300, function()
        _M._flush_bucket("5m", "1h")
    end)

    ngx.timer.every(config.statistics.persist_interval or 300, function()
        _M.persist()
    end)
end

-- 记录请求统计
function _M.log_request(ctx)
    local status = tonumber(ngx.var.status) or 0
    local bytes = tonumber(ngx.var.body_bytes_sent) or 0
    local time = tonumber(ngx.var.request_time) or 0
    local uri = _M.normalize_uri(ngx.var.uri)

    -- 写入短期桶（1 分钟）
    local key = "1m:" .. uri
    local shared = ngx.shared.statistics

    -- shared dict incr 使用 init 参数初始化缺失 key
    shared:incr(key .. ":count", 1, 0)
    shared:incr(key .. ":bytes", bytes, 0)
    shared:incr(key .. ":time", time, 0)
    shared:incr(key .. ":status_" .. status, 1, 0)
    _M.add_index("1m", uri)
end

-- 获取统计报告
function _M.report(period)
    local bucket = period or "1m"
    local shared = ngx.shared.statistics
    local uris = _M.get_index(bucket)

    local report = {}
    for _, uri in ipairs(uris) do
        local key = bucket .. ":" .. uri
        report[uri] = {
            count = shared:get(key .. ":count") or 0,
            bytes = shared:get(key .. ":bytes") or 0,
            time = shared:get(key .. ":time") or 0,
            status = _M._get_status_dist(shared, key),
        }
    end

    return report
end

function _M.add_index(bucket, uri)
    local shared = ngx.shared.statistics
    local index_key = "index:" .. bucket
    local max_keys = config.statistics.max_uri_keys or 10000
    -- 实现时维护一个受控 URI 列表和位置映射，超过 max_keys 时按 LRU 淘汰
    lru_index.add(shared, index_key, uri, max_keys)
end

function _M.get_index(bucket)
    local shared = ngx.shared.statistics
    local index_key = "index:" .. bucket
    return lru_index.list(shared, index_key)
end

function _M.normalize_uri(uri)
    -- 归一化动态 URI，避免统计 key 高基数爆炸
    -- 例如 /user/123/order/456 归一为 /user/:id/order/:id
    return uri
end

function _M.persist()
    -- 定期把长期桶写入 statistics.json，启动时可恢复
end

return _M
```

**关键改进**：
- 按时间窗口聚合（1m/5m/1h/all）
- 减少写入次数（一次请求只写一个桶）
- 定时器自动滚动聚合
- 统计 key 必须 URI 归一化并限制最大基数，超限归入 `__overflow__`
- API 查询使用维护好的 index，不使用 `get_keys(0)` 全量扫描
- `add_index(bucket, uri)` 写入 `index:<bucket>` 受控列表，列表采用 LRU 淘汰，超过 `max_uri_keys` 时丢弃最早记录
- `get_index(bucket)` 只从 `index:<bucket>` 读取 URI 列表，禁止退回 `get_keys(0)`
- 长期统计定时持久化到磁盘，Nginx 重启后可恢复
- `/metrics` 可导出 Prometheus 格式核心指标

---

### 4.7 认证系统 (`api/auth.lua`)

**设计目标**：可插拔认证方式、安全默认值、关键操作防 CSRF 和限流。

```lua
local _M = {}

-- 认证策略注册表
_M.strategies = {}

-- 注册认证策略
function _M.register(name, strategy)
    _M.strategies[name] = strategy
end

-- 默认策略：session-based
_M.strategies["session"] = {
    check = function(ctx)
        local cookie = require "cookie"
        local cookie_obj = cookie:new()
        local fields = cookie_obj:get_all()

        local prefix = config.cookie_prefix
        local token = fields[prefix .. "_session"]

        if not token then
            return false
        end

        local ok, payload = session.verify(token, config.security.session_secret)
        if not ok or payload.expire_at < ngx.time() then
            return false
        end

        for _, admin in ipairs(config.admin) do
            if admin.user == payload.user and admin.enable then
                ctx.set_data(ctx, "auth:user", payload.user)
                return true
            end
        end

        return false
    end,

    login = function(user, password)
        if not rate_limit.allow("login:" .. ngx.var.remote_addr) then
            return false, "too_many_attempts"
        end

        for _, admin in ipairs(config.admin) do
            if admin.user == user and admin.enable then
                if password_hash.verify(password, admin.password_hash) then
                    local token = session.sign({
                        user = user,
                        expire_at = ngx.time() + (config.security.session_ttl or 3600),
                        nonce = random.bytes(16),
                    }, config.security.session_secret)
                    return true, token
                end
            end
        end
        return false
    end,

    logout = function(ctx)
        -- 清除 cookie
    end,
}

-- 认证中间件
function _M.middleware(ctx)
    local strategy_name = config.auth_strategy or "session"
    local strategy = _M.strategies[strategy_name]

    if not strategy then
        ngx.log(ngx.ERR, "auth strategy not found: ", strategy_name)
        return false
    end

    if not strategy.check(ctx) then
        return false
    end

    if _M.is_mutating_request(ctx) and not csrf.verify(ctx) then
        return false
    end

    return true
end

return _M
```

**安全要求**：
- 管理员密码只保存 `password_hash`，禁止明文密码进入配置文件
- Session 使用 HMAC 签名、随机 nonce、过期时间和固定密钥轮换策略
- v2 认证不再依赖 `encrypt_seed`，会话密钥统一来自 `config.security.session_secret`
- 登录、配置保存、回滚、导入导出接口必须限流
- Cookie 必须设置 `HttpOnly; SameSite=Strict`，HTTPS 下必须设置 `Secure`
- 所有变更型 API 必须校验 CSRF token
- 代理 TLS 默认开启证书校验，只有显式配置才允许跳过

---

#### 认证与限流辅助模块接口

```lua
-- core/session.lua
session.sign(payload, secret) -> token
session.verify(token, secret) -> ok, payload_or_err

-- core/password_hash.lua
password_hash.hash(password) -> encoded_hash
password_hash.verify(password, encoded_hash) -> boolean

-- core/random.lua
random.bytes(length) -> binary_string
random.hex(length) -> hex_string

-- api/rate_limit.lua
rate_limit.allow(key) -> boolean
rate_limit.allow(key, limit, window) -> boolean
```

**接口约定**：
- `session.sign` 只签名 JSON payload，不保存服务端 session 状态
- `session.verify` 必须校验签名、过期时间和密钥版本
- `password_hash` 优先使用 bcrypt/argon2，无法启用时必须拒绝启动而不是降级到 MD5
- `random.bytes` 必须使用 OpenResty/Nginx 可用的安全随机源
- `rate_limit.allow()` 返回 `true` 表示允许继续，请求超限时返回 `false`

---

### 4.8 上游健康检查 (`plugin/proxy_pass/health_check.lua`)

**设计目标**：代理只选择健康节点，故障节点自动摘除并自动恢复。

```lua
local _M = {}
local metrics = require "core.metrics"

function _M.init()
    -- 该函数从 init_worker_by_lua 调用
    ngx.timer.every(config.proxy.health_check_interval or 5, function()
        _M.active_check_all()
    end)
end

function _M.active_check_all()
    for name, upstream in pairs(config.backend_upstream) do
        for _, node in ipairs(upstream.nodes or {}) do
            _M.check_node(name, node)
        end
    end
end

function _M.check_node(upstream_name, node)
    local key = upstream_name .. ":" .. node.host .. ":" .. node.port
    local shared = ngx.shared.healthcheck
    local ok = _M.probe_node(node)
    if ok then
        shared:delete(key .. ":state")
        shared:delete(key .. ":failures")
        shared:delete(key .. ":last_error")
        metrics.gauge("upstream_healthy", 1, { upstream = upstream_name, node = node.host })
        return true
    end
    _M.report_failure(upstream_name, node, "probe failed")
    return false
end

function _M.probe_node(node)
    -- 根据 upstream.health_check 配置执行 TCP 或 HTTP 探测
    return active_probe.run(node)
end

function _M.report_failure(upstream_name, node, reason)
    local key = upstream_name .. ":" .. node.host .. ":" .. node.port
    local shared = ngx.shared.healthcheck
    local failures = shared:incr(key .. ":failures", 1, 0)
    if failures >= (node.max_fails or 3) then
        shared:set(key .. ":state", "unhealthy", node.fail_timeout or 30)
    end
    shared:set(key .. ":last_error", reason, 60)
    metrics.gauge("upstream_healthy", 0, { upstream = upstream_name, node = node.host })
end

function _M.is_healthy(upstream_name, node)
    local key = upstream_name .. ":" .. node.host .. ":" .. node.port
    return ngx.shared.healthcheck:get(key .. ":state") ~= "unhealthy"
end

return _M
```

**关键要求**：
- 主动健康检查负责发现恢复，被动失败计数负责快速摘除故障节点
- `check_node()` 探测成功时清理 `state/failures/last_error`，节点恢复为 healthy
- 健康状态放入 `lua_shared_dict healthcheck`，所有 worker 共享
- `balancer.select_healthy()` 只能返回健康节点
- 没有健康节点时，代理插件返回 503，不继续尝试随机节点

---

### 4.9 可观测性 (`core/observability.lua`)

**设计目标**：内置 metrics、trace、健康状态和插件耗时。

```lua
local _M = {}

function _M.init()
    -- 空实现也必须保留，便于 init_worker_by_lua 统一初始化模块
    -- 后续可在此注册 worker 级状态采集定时器
end

function _M.start_plugin_timer(ctx, plugin_name)
    ctx.set_data(ctx, "timing:" .. plugin_name, ngx.now())
end

function _M.finish_plugin_timer(ctx, plugin_name)
    local start = ctx.get_data(ctx, "timing:" .. plugin_name)
    if start then
        metrics.observe("plugin_duration_seconds", ngx.now() - start, {
            plugin = plugin_name
        })
    end
end

function _M.export_prometheus()
    -- 导出请求量、状态码、插件耗时、上游健康、配置版本、错误计数
end

return _M
```

```lua
-- core/metrics.lua
local _M = {}

function _M.init()
    -- 初始化受控指标 index。重复调用必须幂等。
    ngx.shared.metrics:add("__metrics_index", "{}", 0)
end

function _M.incr(name, value, labels)
    local key = _M.key(name, labels)
    ngx.shared.metrics:incr(key, value or 1, 0)
end

function _M.observe(name, value, labels)
    -- histogram 简化表示：count/sum/bucket 分别写入 shared dict
    _M.incr(name .. "_count", 1, labels)
    _M.incr(name .. "_sum", value, labels)
end

function _M.gauge(name, value, labels)
    ngx.shared.metrics:set(_M.key(name, labels), value)
end

function _M.export_prometheus()
    -- 从受控 index 导出 Prometheus 文本格式，不在请求路径 get_keys(0)
end

return _M
```

**关键要求**：
- `/metrics` 导出 Prometheus 格式指标
- `metrics.incr`、`metrics.observe`、`metrics.gauge` 由 `core/metrics.lua` 统一封装，插件不得直接拼 shared dict key
- `metrics.init()` 和 `observability.init()` 必须存在且幂等，即使初期为空实现也要保留
- `/status` 返回配置 hash、插件状态、upstream 健康状态
- `trace_id` 从请求头读取或生成，并透传给后端
- access log 必须包含 `trace_id`、动作结果、插件耗时、upstream 目标

---

## 五、请求处理流程

### 5.1 初始化阶段 (`init_by_lua` / `init_worker_by_lua`)

```lua
-- core/init.lua
local _M = {}

function _M.init()
    -- 1. 加载配置（仅启动时）
    config.load_from_file()

    -- 2. 初始化共享内存
    _M.init_shared_dict()

    -- 3. 注册匹配器
    matcher.register("URI", uri_matcher)
    matcher.register("IP", ip_matcher)
    matcher.register("UserAgent", ua_matcher)
    matcher.register("Host", host_matcher)
    matcher.register("Referer", referer_matcher)
    matcher.register("Args", args_matcher)
    matcher.register("Header", header_matcher)
    matcher.register("Cookie", cookie_matcher)
    matcher.register("Method", method_matcher)

    -- 4. 注册插件（按优先级排序）
    plugin.register(filter_plugin)       -- priority: 100
    plugin.register(frequency_limit_plugin) -- priority: 200
    plugin.register(browser_verify_plugin)  -- priority: 300
    plugin.register(router_plugin)      -- priority: 400
    plugin.register(proxy_pass_plugin)  -- priority: 500
    plugin.register(static_file_plugin) -- priority: 600

    -- 5. 初始化所有插件
    plugin.init_all()
end

function _M.init_shared_dict()
    -- 使用统一的 shared dict 管理
    local shared = ngx.shared.vn_config
    shared:set('config_hash', config.local_hash)
end

function _M.init_worker()
    -- worker 级初始化必须在 init_worker_by_lua 启动
    -- 顺序依赖：metrics 先初始化，其他模块才能上报指标
    metrics.init()
    observability.init()
    statistics.init()
    health_check.init()
end

return _M
```

**初始化顺序说明**：
- `metrics.init()` 先建立指标 index 和 shared dict 封装
- `observability.init()` 注册 trace、状态导出和插件耗时采集
- `statistics.init()` 启动请求统计滚动与持久化定时器
- `health_check.init()` 最后启动上游探测，健康检查可安全上报 metrics

### 5.2 重写阶段 (`rewrite_by_lua`)

```lua
-- on_rewrite.lua
local _M = {}

function _M.run()
    -- 1. 检查配置更新（仅比较 hash，零 I/O）
    config.check_update()

    -- 2. 创建请求上下文
    local ctx = context.new()
    ngx.ctx.vn_ctx = ctx

    -- 3. 执行 scheme 锁
    scheme_lock.execute(ctx)

    -- 4. 执行重定向规则
    redirect.execute(ctx)

    -- 5. 执行 URI 重写规则
    rewrite.execute(ctx)

    -- 6. 应用 rewrite 阶段动作
    rule_engine.apply(ctx, "rewrite")
end

return _M
```

### 5.3 访问阶段 (`access_by_lua`)

```lua
-- on_access.lua
local _M = {}

function _M.run()
    local ctx = ngx.ctx.vn_ctx
    if not ctx then
        return
    end

    -- 检查是否已在 rewrite 阶段做出决策
    if ctx.has_decision(ctx) then
        return
    end

    -- 执行所有插件（带短路）
    plugin.execute_access(ctx)

    -- 应用访问阶段动作，例如 block/redirect/proxy 变量
    rule_engine.apply(ctx, "access")
end

return _M
```

### 5.4 日志阶段 (`log_by_lua`)

```lua
-- on_log.lua
local _M = {}

function _M.run()
    local ctx = ngx.ctx.vn_ctx
    if not ctx then
        return
    end

    -- 执行所有插件的日志钩子
    plugin.execute_log(ctx)
end

return _M
```

---

## 六、插件实现示例

### 6.1 防火墙插件 (`plugin/filter/init.lua`)

```lua
local _M = {}

_M.name = "filter"
_M.priority = 100
_M.default_enable = true
_M.critical = true

function _M.on_access(ctx)
    local rules = config.rule.filter or {}

    for _, rule in ipairs(rules) do
        if not rule.enable then
            goto continue
        end

        local matched = matcher.test(rule.matcher, ctx)

        if matched then
            if rule.action == "accept" then
                ctx.set_action(ctx, "accept")
                return  -- 短路：放行
            elseif rule.action == "block" then
                ctx.set_data(ctx, "filter:blocked", true)
                ctx.set_action(ctx, "block", {
                    code = rule.code or 403,
                    response = rule.response
                })
                return  -- 短路：拦截
            end
        end

        ::continue::
    end
end

return _M
```

### 6.2 反向代理插件 (`plugin/proxy_pass/init.lua`)

```lua
local _M = {}

_M.name = "proxy_pass"
_M.priority = 500
_M.default_enable = true
_M.critical = true

function _M.on_access(ctx)
    local rules = config.rule.proxy_pass or {}

    for _, rule in ipairs(rules) do
        if not rule.enable then
            goto continue
        end

        local matched = matcher.test(rule.matcher, ctx)

        if matched then
            -- 设置后端信息
            local upstream = config.backend_upstream[rule.upstream]
            local node = balancer.select_healthy(upstream)
            if not node then
                ctx.set_action(ctx, "block", { code = 503, response = "No healthy upstream" })
                return
            end

            ctx.set_data(ctx, "proxy:target", node.host .. ":" .. node.port)
            ctx.set_action(ctx, "proxy", {
                scheme = node.scheme,
                host = node.host,
                port = node.port,
                proxy_host = rule.proxy_host,
                sni = rule.sni or node.host,
                websocket = rule.websocket == true,
            })
            return
        end

        ::continue::
    end
end

return _M
```

#### `proxy_pass/balancer.lua` 接口

```lua
local _M = {}
local ngx_balancer = require "ngx.balancer"

function _M.select_healthy(upstream)
    -- access 阶段调用，只从健康节点中按 upstream.method 选择节点
    -- 返回 { scheme, host, port, weight }，不直接调用 ngx.balancer
end

function _M.run()
    -- balancer_by_lua 阶段调用，读取 access 阶段已经选中的目标
    local host = ngx.var.vn_proxy_host
    local port = tonumber(ngx.var.vn_proxy_port)
    if not host or host == "" or not port then
        ngx.log(ngx.ERR, "proxy target is empty")
        return ngx.exit(500)
    end

    local ok, err = ngx_balancer.set_current_peer(host, port)
    if not ok then
        ngx.log(ngx.ERR, "balancer failed: ", err)
        return ngx.exit(502)
    end
end

return _M
```

**代理交接约定**：
- `proxy_pass` 插件在 access 阶段调用 `select_healthy()` 选出健康节点
- `rule_engine.apply()` 把已选节点写入 `vn_proxy_host`、`vn_proxy_port`、`vn_proxy_scheme`、`vn_proxy_sni`
- `balancer_by_lua` 只读取这些变量并调用 `set_current_peer(host, port)`
- balancer 阶段不重新选节点，避免 access 阶段日志、统计和真实转发目标不一致

### 6.3 频率限制插件 (`plugin/frequency_limit/init.lua`)

```lua
local _M = {}

_M.name = "frequency_limit"
_M.priority = 200
_M.default_enable = true
_M.critical = true

function _M.on_access(ctx)
    local rules = config.rule.frequency_limit or {}
    local shared = ngx.shared.frequency_limit

    for _, rule in ipairs(rules) do
        if not rule.enable then
            goto continue
        end

        if matcher.test(rule.matcher, ctx) then
            local key = limiter.build_key(rule.key or "ip", ctx)
            local limit = rule.limit or 60
            local window = rule.window or 60
            local current = shared:incr(key, 1, 0, window)

            if current > limit then
                ctx.set_data(ctx, "frequency_limit:limited", true)
                ctx.set_action(ctx, "block", {
                    code = rule.code or 429,
                    response = rule.response or "Too Many Requests"
                })
                return
            end
        end

        ::continue::
    end
end

return _M
```

**关键要求**：
- 规则复用 `config.rule.frequency_limit` 的 matcher/action 结构
- key 可按 IP、URI、Host、Cookie、认证用户或组合维度生成
- `ngx.shared.frequency_limit` 写入必须带窗口 TTL
- 限流命中时设置 `ctx.data["frequency_limit:limited"]`，供日志和统计使用

#### `limiter.build_key()` 接口

```lua
limiter.build_key("ip", ctx) -> "fl:ip:<remote_addr>"
limiter.build_key("uri", ctx) -> "fl:uri:<normalized_uri>"
limiter.build_key("user", ctx) -> "fl:user:<auth_user>"
limiter.build_key({ "ip", "uri" }, ctx) -> "fl:combo:<remote_addr>:<normalized_uri>"
```

**key 要求**：
- key 必须带 `fl:` 前缀，避免与其他 shared dict 数据冲突
- URI 必须复用统计模块的归一化逻辑，避免高基数
- 未登录用户使用 `anonymous`，不能把空 user 拼进 key
- 组合 key 的字段顺序必须稳定，由配置编译阶段固定

### 6.4 浏览器验证插件 (`plugin/browser_verify/init.lua`)

**定位**：
- `browser_verify` 用于对命中规则的客户端发起 Cookie 或 JavaScript 验证
- Cookie 签名和过期校验统一使用 `core/session.lua`，不再使用旧的 seed 拼接逻辑
- 验证通过后在 `ctx.data["browser_verify:passed"]` 记录结果，供日志和统计使用
- 验证失败时返回 `response` action 或跳转到验证页面，具体响应模板来自 `config.response`

### 6.5 Router 插件 (`plugin/router/init.lua`)

**定位**：
- `router` 只负责识别管理面板、API、静态资源等 VeryNginx 自身路径
- 管理 API 的认证与 CSRF 校验委托给 `api/auth.lua` 和 `api/csrf.lua`
- 业务代理、防火墙、限流规则不应直接耦合管理面板路径判断
- router 命中管理路径后设置 `ctx.data["router:target"]`，并交由 API 或 dashboard handler 处理

### 6.6 静态文件插件 (`plugin/static_file/init.lua`)

```lua
local _M = {}

_M.name = "static_file"
_M.priority = 600
_M.default_enable = true
_M.critical = false

function _M.on_access(ctx)
    local rules = config.rule.static_file or {}

    for _, rule in ipairs(rules) do
        if not rule.enable then
            goto continue
        end

        if matcher.test(rule.matcher, ctx) then
            ctx.set_data(ctx, "static:root", rule.root)
            ctx.set_action(ctx, "static", {
                root = rule.root,
                path = rule.path or ctx.request.uri,
                expires = rule.expires or "epoch"
            })
            return
        end

        ::continue::
    end
end

return _M
```

**关键要求**：
- `root` 必须来自配置白名单并在保存时校验存在
- `path` 必须归一化，禁止 `..`、软链接逃逸和绝对路径覆盖
- `expires` 支持 `epoch`、秒数或标准缓存策略字符串
- 大文件优先交给 Nginx 固定 location，Lua 静态服务只用于受控小文件或管理面板资源

#### `static_file.serve()` 接口

```lua
local _M = {}

function _M.serve(root, path, expires)
    local safe_path, err = path_security.normalize(root, path)
    if not safe_path then
        ngx.status = 403
        ngx.say("Forbidden")
        return ngx.exit(403)
    end

    local stat = file_stat(safe_path)
    if not stat then
        return ngx.exit(404)
    end

    if stat.size > (config.static_file.x_accel_threshold or 1048576) then
        ngx.header["X-Accel-Redirect"] = x_accel.map(root, safe_path)
        return ngx.exit(200)
    end

    cache_header.set_expires(expires)
    return send_file(safe_path)
end

return _M
```

**路径与文件行为**：
- `normalize(root, path)` 必须拒绝 `..`、绝对路径覆盖、NUL 字符和 URL 编码绕过
- 软链接默认拒绝，除非配置显式允许并且解析后的真实路径仍在 `root` 内
- 文件不存在返回 404，不 fall-through 到 proxy，避免静态规则被绕过
- 大文件使用 `X-Accel-Redirect` 交给 Nginx 内部 location 输出，小文件可由 Lua 直接输出

### 6.7 DNS 缓存 (`plugin/proxy_pass/dns_cache.lua`)

**设计目标**：域名 upstream 解析可控、可缓存、可失效，解析失败时允许短时间使用旧记录。

```lua
local _M = {}

function _M.cache_key(host, record_type)
    return "dns:" .. string.lower(host) .. ":" .. (record_type or "A")
end

function _M.resolve(host, record_type, dns_conf)
    dns_conf = dns_conf or {}
    local key = _M.cache_key(host, record_type)
    local cached = ngx.shared.dns_cache:get(key)
    if cached then
        return json.decode(cached)
    end

    local answers, err = resolver.query(host, { qtype = record_type or "A" })
    if not answers then
        return _M.resolve_stale(key, dns_conf), err
    end

    local ttl = _M.effective_ttl(answers.ttl, dns_conf)
    ngx.shared.dns_cache:set(key, json.encode(answers), ttl)
    ngx.shared.dns_cache:set(key .. ":stale", json.encode(answers), ttl + (dns_conf.stale_if_error or 60))
    return answers
end

function _M.effective_ttl(ttl, dns_conf)
    ttl = ttl or dns_conf.default_ttl or 30
    ttl = math.max(ttl, dns_conf.min_ttl or 5)
    ttl = math.min(ttl, dns_conf.max_ttl or 300)
    return ttl
end

function _M.resolve_stale(key, dns_conf)
    if (dns_conf.stale_if_error or 0) <= 0 then
        return nil
    end
    local stale = ngx.shared.dns_cache:get(key .. ":stale")
    if stale then
        return json.decode(stale)
    end
    return nil
end

return _M
```

**关键要求**：
- 缓存 key 格式为 `dns:<lowercase-host>:<record-type>`，例如 `dns:api.example.com:A`
- v2 缓存 A/AAAA 记录，SRV 暂不作为核心路由能力，CAA 不用于路由决策
- TTL 默认使用 DNS 响应 TTL，再被 `min_ttl` 和 `max_ttl` 覆盖
- `stale_if_error` 表示正常 TTL 过期后，解析失败时仍可使用旧记录的额外秒数
- 配置保存、upstream 节点变更、resolver 配置变更时必须删除相关 key
- 健康检查发现域名解析结果全部不可达时，应触发该域名缓存失效并重新解析
- 内存估算：每个域名每种记录约 0.5-2KB，1000 个域名同时缓存 A/AAAA 约需 1-4MB shared dict

---

## 七、Nginx 配置片段

### 7.1 `in_http_block.conf`

```nginx
# 共享内存（统一管理）
lua_shared_dict vn_config 2m;
lua_shared_dict vn_locks 1m;
lua_shared_dict statistics 20m;
lua_shared_dict metrics 10m;
lua_shared_dict healthcheck 10m;
lua_shared_dict dns_cache 4m;
lua_shared_dict frequency_limit 10m;

# Lua 路径
lua_package_path '/opt/verynginx/verynginx/?.lua;;';
lua_package_cpath '/opt/verynginx/verynginx/?.so;;';
lua_code_cache on;

# TLS 校验默认开启
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
lua_ssl_verify_depth 3;

# WebSocket 连接升级
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

# 主进程初始化
init_by_lua_block {
    require("core.init").init()
}

# worker 级定时器和健康检查
init_worker_by_lua_block {
    require("core.init").init_worker()
}

upstream vn_dynamic_upstream {
    server 0.0.0.1;
    balancer_by_lua_block {
        require("plugin.proxy_pass.balancer").run()
    }
    keepalive 128;
}
```

### 7.2 `in_server_block.conf`

```nginx
# 主业务 location，代理变量由 access_by_lua 设置，默认值用于安全兜底
location / {
    set $vn_proxy_scheme "http";
    set $vn_proxy_host "";
    set $vn_proxy_port "80";
    set $vn_proxy_sni "";

    # 重写阶段
    rewrite_by_lua_file /opt/verynginx/verynginx/on_rewrite.lua;

    # 访问阶段
    access_by_lua_file /opt/verynginx/verynginx/on_access.lua;

    # 代理不依赖 ngx.exec，统一进入动态 upstream
    proxy_http_version 1.1;
    proxy_set_header Host $vn_proxy_host;
    proxy_set_header X-Request-Id $request_id;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_ssl_name $vn_proxy_sni;
    proxy_ssl_server_name on;
    proxy_ssl_verify off;
    proxy_connect_timeout 3s;
    proxy_read_timeout 60s;
    proxy_send_timeout 60s;
    proxy_pass http://vn_dynamic_upstream;

    # 日志阶段
    log_by_lua_file /opt/verynginx/verynginx/on_log.lua;
}

# 管理面板静态资源走固定 location，不作为业务规则控制流
location /verynginx/static/ {
    alias /opt/verynginx/verynginx/dashboard/;
    expires epoch;
}
```

---

## 八、性能与可靠性设计要点

### 8.1 热更新与配置一致性

| 目标 | 设计 |
|------|------|
| 请求路径零 I/O | 每个请求只比较 `shared dict` 中的 `config_hash` |
| 配置变更原子性 | `validate_and_compile` 成功后写 tmp 文件，再 rename 到正式文件 |
| 多 worker 一致性 | 保存方更新本地快照和 `config_hash`，其他 worker 懒加载新快照 |
| 并发保存安全 | `shared dict add` 实现短租约锁，保存失败必须释放锁 |
| 可回滚 | 保存前保留最近 N 个 `config.json` 备份，提供 `rollback` API |

### 8.2 匹配优化

| 目标 | 设计 |
|------|------|
| Body 延迟读取 | 仅 Args/Body matcher 需要时读取 |
| Body 安全限制 | 限制 `max_size` 和 `max_args`，body 落盘时按规则 fail-closed 或跳过 |
| 匹配缓存 | 单请求内最多缓存 `matcher_cache_size` 条结果 |
| 正则性能 | 配置加载阶段校验正则，运行期使用 PCRE JIT |
| 未知条件处理 | 配置加载阶段拒绝未知 matcher，运行期兜底不匹配 |

### 8.3 短路与动作应用

| 场景 | 设计 |
|------|------|
| `block` / `redirect` | 立即执行终止动作 |
| `accept` | 终止当前插件链并放行到后续 Nginx 流程 |
| `rewrite` | 只在 rewrite 阶段允许修改 URI |
| `proxy` / `static` | `proxy` 设置受控变量进入动态 upstream，`static` 通过 `static_file.serve` 校验后输出 |
| 插件崩溃 | critical 插件 fail-closed，非 critical 插件 fail-open |

### 8.4 统计与可观测性

| 目标 | 设计 |
|------|------|
| 写入次数 | 每请求只写 1m 桶的核心指标 |
| 时间窗口 | 1m、5m、1h、all 定时滚动 |
| 高基数保护 | URI 归一化，超限归入 `__overflow__` |
| 查询性能 | 维护 bucket index，不使用 `get_keys(0)` 做频繁查询 |
| 持久化 | 长期统计定时写入 `statistics.json`，启动时恢复 |
| 指标导出 | `/metrics` 导出 Prometheus 格式指标 |
| Trace | `trace_id` 进入日志、响应头、代理请求头和插件耗时记录 |

### 8.5 代理与上游可靠性

| 目标 | 设计 |
|------|------|
| 动态 upstream | access 阶段选择健康节点，`balancer_by_lua` 只调用 `set_current_peer` |
| 健康检查 | 主动探测 + 被动失败计数，超过阈值临时摘除 |
| TLS 默认安全 | 默认 `proxy_ssl_verify on`，配置可声明 CA、SNI、verify depth |
| DNS 缓存 | A/AAAA 解析缓存尊重 TTL，支持 stale-if-error 和配置变更失效 |
| WebSocket | 默认保留 Upgrade/Connection 头，规则可显式开启长连接策略 |
| 超时与重试 | upstream 配置 connect/read/send timeout、retry、fail_timeout |
| 无可用节点 | fail-closed，返回 503，并记录 upstream 状态 |

---

## 九、v2 配置结构

v2 使用全新配置结构，不提供旧配置自动转换。配置必须先通过 schema 校验、引用完整性校验和编译步骤，才能保存并激活。

```json
{
    "version": "2.0",
    "base_uri": "/verynginx",
    "cookie_prefix": "verynginx",
    "config_save_lock_ttl": 60,
    "security": {
        "session_ttl": 3600,
        "csrf": true,
        "rate_limit": {
            "login": "10/m",
            "config_save": "30/m"
        }
    },
    "body": {
        "max_size": 1048576,
        "max_args": 100,
        "on_error": "fail_closed"
    },
    "plugin": {
        "filter": { "enable": true, "priority": 100, "critical": true },
        "frequency_limit": { "enable": true, "priority": 200, "critical": true },
        "browser_verify": { "enable": false, "priority": 300, "critical": true },
        "proxy_pass": { "enable": true, "priority": 500, "critical": true },
        "static_file": { "enable": true, "priority": 600, "critical": false },
        "summary": { "enable": true, "priority": 900, "critical": false }
    },
    "auth_strategy": "session",
    "statistics": {
        "buckets": ["1m", "5m", "1h", "all"],
        "flush_interval": 60,
        "persist_interval": 300,
        "max_uri_keys": 10000
    },
    "observability": {
        "metrics": true,
        "trace_header": "X-Request-Id",
        "plugin_timing": true
    },
    "proxy": {
        "health_check_interval": 5
    },
    "matcher": {
        "block_sql_injection": {
            "Args": {
                "name_operator": "*",
                "operator": "≈",
                "value": "(union\\s+select|sleep\\()",
                "on_body_error": "fail_closed"
            }
        }
    },
    "rule": {
        "filter": [
            {
                "enable": true,
                "matcher": "block_sql_injection",
                "action": "block",
                "code": 403,
                "response": "forbidden_json"
            }
        ],
        "frequency_limit": [],
        "proxy_pass": [
            {
                "enable": true,
                "matcher": {},
                "action": "proxy",
                "upstream": "api_backend",
                "proxy_host": "api.example.com"
            }
        ],
        "static_file": []
    },
    "backend_upstream": {
        "api_backend": {
            "method": "round_robin",
            "nodes": [
                { "scheme": "https", "host": "10.0.0.1", "port": 443, "weight": 1 }
            ],
            "health_check": {
                "interval": 5,
                "timeout": 2,
                "max_fails": 3,
                "fail_timeout": 30,
                "path": "/health"
            },
            "tls": {
                "verify": true,
                "sni": "api.example.com"
            },
            "timeout": {
                "connect": 3,
                "read": 60,
                "send": 60
            },
            "dns": {
                "min_ttl": 5,
                "max_ttl": 300,
                "stale_if_error": 60
            }
        }
    },
    "response": {
        "forbidden_json": {
            "code": 403,
            "content_type": "application/json",
            "body": "{\"error\":\"forbidden\"}"
        },
        "maintenance_html": {
            "code": 503,
            "content_type": "text/html; charset=utf-8",
            "body": "<h1>Maintenance</h1>"
        }
    },
    "admin": []
}
```

**配置保存要求**：
- 禁止保存未知字段和未知插件
- `admin` 只能保存 `password_hash`，不能保存明文密码
- `rule` 引用的 matcher、action、response、upstream 必须存在
- Args matcher 的 `condition.on_body_error` 只能取 `"match"`、`"skip"`、`"fail_closed"`
- upstream 必须声明 health check、timeout、TLS 校验策略
- `response` 是可复用响应模板，`block` 可内嵌响应体，也可引用 `response` 模板；独立 `response` action 用于非拦截类自定义响应
- `config_save_lock_ttl` 默认 60 秒，保存流程必须使用 token 校验和续期，释放锁前必须确认 token 匹配
- 保存前创建备份，保存后立即激活当前 worker 并更新 `config_hash`

---

## 十、测试策略

### 10.1 单元测试

- 匹配器纯函数测试（无 nginx 依赖）
- 规则引擎短路测试
- 配置 schema 校验、编译、回滚测试
- 配置保存锁 token、TTL 续期、并发保存拒绝测试
- 认证、CSRF、限流、session 过期测试
- 统计 URI 归一化、高基数限制、持久化测试
- response 模板解析、独立 response action、block 引用模板测试
- Args matcher `on_body_error` 优先级和非法值拒绝测试
- `static_file.serve` 路径归一化、软链接和大文件分流测试

### 10.2 集成测试

- 端到端请求测试（OpenResty + Docker）
- 插件加载/卸载测试
- 热更新测试
- critical 插件异常 fail-closed 测试
- 代理健康检查、故障摘除、恢复测试
- balancer_by_lua 读取已选节点并转发到 `set_current_peer` 测试
- WebSocket 代理测试
- frequency_limit 命中和窗口过期测试
- static_file 路径归一化和越权路径拒绝测试
- DNS 缓存 key、TTL 覆盖、失效、stale-if-error、内存上限测试
- `/metrics` 指标导出测试

### 10.3 性能测试

- 基准测试：空规则、100 条规则、1000 条规则的 RPS 和 P99 延迟
- 压力测试：10k+ 并发连接
- 内存泄漏检测：长时间运行
- 热更新压力测试：并发请求下反复保存配置，确保无 5xx 抖动

### 10.4 测试工具与门禁

- 纯 Lua 单元测试：`busted`
- OpenResty 集成测试：`Test::Nginx::Socket` 或 Docker Compose
- 静态检查：`luacheck`
- 性能测试：`wrk` 或 `vegeta`
- CI 门禁：单元测试、集成测试、静态检查必须全通过；性能测试记录基线并阻止明显退化

---

## 十一、实施路线图

| 阶段 | 任务 | 产出 |
|------|------|------|
| **Phase 1** | 核心框架（config + context + plugin + action apply） | 可运行的空框架 |
| **Phase 2** | 匹配器系统 + 规则引擎 + 配置编译校验 | 可配置规则 |
| **Phase 3** | 安全基线（auth + CSRF + 限流 + Cookie 安全） | 管理接口安全可用 |
| **Phase 4** | 插件实现（filter + frequency + browser_verify + static） | 防护能力完整 |
| **Phase 5** | 动态代理（balancer + health check + TLS + WebSocket） | 代理能力完整 |
| **Phase 6** | 统计、持久化、metrics、trace | 可观测 |
| **Phase 7** | 管理面板 + 全量测试 + 性能基线 | 可上线 |

---

## 十二、总结

v2.0 的核心设计原则：

1. **关注点分离**：配置、匹配、动作、统计、认证各自独立
2. **无副作用**：匹配器是纯函数，body 延迟读取
3. **可插拔**：插件化架构，按需启用
4. **安全默认值**：认证、CSRF、限流、Cookie、TLS 校验默认安全
5. **高性能**：热更新零 I/O、短路优化、统计聚合
6. **可观测**：metrics、traceId、插件耗时、健康状态内置
7. **可测试**：核心逻辑可脱离 nginx 单元测试，OpenResty 行为有集成测试覆盖

---

## 十三、v2 开发前验收清单

以下条目属于 v2.0 必选范围，不作为后续版本延期项。

### 13.1 配置与热更新

- 配置保存必须经过 schema 校验、引用完整性校验和编译校验
- 保存流程必须支持带 token 的并发锁、TTL 续期、tmp 文件、原子 rename、备份、回滚
- 运行时配置必须是不可变快照，插件不得直接修改
- 热更新必须验证多 worker 场景下不会加载半写入配置

### 13.2 安全基线

- 管理员密码必须哈希存储
- Session 必须签名、带过期时间、支持密钥轮换
- 变更型 API 必须启用 CSRF
- 登录、配置保存、回滚接口必须限流
- Cookie 必须设置 `HttpOnly`、`SameSite=Strict`，HTTPS 下必须设置 `Secure`
- 代理 TLS 默认校验证书和 SNI

### 13.3 插件与规则执行

- 关键插件默认 fail-closed
- 插件启停、优先级、critical 策略必须全部来自配置
- 规则动作必须通过统一 `apply()` 落地
- 插件间通信只能使用 `ctx.data` 命名空间
- 未知 matcher、action、plugin 必须在配置保存时拒绝
- `frequency_limit`、`static_file`、`filter`、`proxy_pass` 都必须复用统一规则结构
- `response` action 和 response 模板必须统一走 `response.resolve`
- `static_file.serve` 必须定义路径安全、404 行为和大文件输出策略

### 13.4 请求体与匹配

- Body matcher 必须受 `max_size`、`max_args` 限制
- body 过大、落盘、解析失败时必须有明确 fail-open 或 fail-closed 策略
- `condition.on_body_error` 必须定义取值、优先级和非法值拒绝规则
- 匹配缓存必须有固定上限
- 组合 matcher 必须有明确 AND、OR、NOT 语义

### 13.5 代理与上游

- 代理必须使用健康节点选择
- 主动健康检查和被动失败计数都必须实现
- 没有健康节点时返回 503
- WebSocket 必须有集成测试覆盖
- 动态代理不依赖 `ngx.exec` 作为业务控制流
- upstream 配置必须包含 nodes、health_check、tls、timeout，域名节点必须经过 DNS cache
- DNS cache 必须定义 key 格式、TTL 覆盖、stale-if-error、失效触发和内存预算
- balancer 阶段必须读取 access 阶段已选节点并调用 `ngx.balancer.set_current_peer`

### 13.6 统计与可观测性

- 统计 key 必须归一化并限制基数
- 长期统计必须持久化并支持启动恢复
- `/metrics` 必须导出 Prometheus 格式指标
- 请求必须携带 `trace_id`，并透传到后端
- 插件耗时、动作结果、上游选择结果必须可记录

### 13.7 测试门禁

- `busted` 单元测试必须覆盖 matcher、rule_engine、config、auth、statistics
- OpenResty 集成测试必须覆盖 rewrite、access、log、balancer、health check
- 安全测试必须覆盖 CSRF、Cookie flags、登录限流、配置保存限流
- 性能测试必须记录空规则、100 条规则、1000 条规则的 RPS 和 P99
- CI 中静态检查、单元测试、集成测试必须全通过
