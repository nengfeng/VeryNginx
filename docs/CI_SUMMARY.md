# CI 通过要点总结

## 核心问题链

1. **`ngx.exit()` 被 `pcall` 吞掉** — `plugin.execute_access()` 用 `pcall` 调用路由插件的 `on_access`，而 `api.dispatch()` 用 `ngx.exit()` 终止请求。`pcall` 捕获了 `ngx.exit()` 抛出的 Lua 错误，请求继续执行到 `rule_engine.apply()`，此时 `ctx.action_result` 为 nil → `_no_backend_error()` → 502。

2. **`ngx.hmac_sha256` 不存在** — OpenResty 1.31.1.1 (alpine-fat 镜像) 不暴露此函数。无效登录（用户名不匹配）不进入 PBKDF2，掩盖了问题；有效登录触发 PBKDF2 才崩溃。

3. **CSRF token 存储域错误** — CSRF token 存在 `ctx.data`（单请求级），下一个请求的 `verify()` 查不到。

## 关键修复点

- **`api/init.lua`** — `ngx.exit()` → `ctx.set_action("response", ...)`，交由 `rule_engine.apply()` 在 pcall 之外处理响应
- **`core/hmac.lua`** — 新建模块，先用 `ngx.hmac_sha256`，若 nil 则用 LuaJIT FFI 调用 OpenSSL 的 `HMAC()` + `EVP_sha256()`
- **`core/session.lua`** — 改用 `hmac.hmac_sha256`（不再直接调 `ngx.hmac_sha256`）
- **`api/csrf.lua`** — token 存入 `ngx.shared.vn_locks` 键为 `csrf:md5(session)` 跨请求共享；`verify()` 中先调 `ngx.req.read_body()`
- **`plugin/router/init.lua`** — `dispatch()` 后检查 `ctx.has_decision()`，有则提前返回（不落入 static 分支）
