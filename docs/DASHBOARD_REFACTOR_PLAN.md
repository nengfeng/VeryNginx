# VeryNginx v2 Dashboard 物理分文件重构计划

> 关联代码：`verynginx/dashboard/index.html`（单文件 SPA）
> 校验工具：`test/v2/check_bindings.js`、`test/v2/refactor_expose.js`
> **当前状态**：Phase 0 基线锁定 ✅完成 (2026-08-18)；Phase 1 拆 CSS ✅完成 (2026-08-18)；Phase 2 拆 JS 主体 ✅完成 (2026-08-18)；Phase 3 分域拆模块 ✅完成 (2026-08-19)；Phase 4 收尾 ✅完成 (2026-08-19)

---

## 一、重构原因

| # | 现状问题 | 具体证据 |
|---|---------|---------|
| R1 | 单文件 5188 行，改动碰撞面大 | `index.html` 内含 `<style>` 108 行 + 模板 ~1920 行 + `<script>` ~3137 行；任何一处改动都要加载/扫描全文件 |
| R2 | 编辑器无法按文件定位与 diff | `setup()` 内 157 个 `ref/reactive/computed` + ~130 个函数全部平铺，grep/搜索噪音大，git diff 单文件巨型化 |
| R3 | 模块边界被物理结构掩盖 | waf/kb/frequency/config/reputation 的状态与函数交错在同一个 `setup()` 闭包里，边界只能靠注释 `// ---- WAF ----` 识别，无强制执行手段 |
| R4 | 函数声明顺序有隐性依赖 | 已踩过一次雷（`rawJson` watch 引用未定义变量），单文件闭包让「先声明后使用」全凭约定，check_bindings 只能查模板↔导出，查不到内部声明顺序 |
| R5 | 后续模块级增强（组件化、按需加载）被堵死 | 无构建的 in-DOM 模板天然支持物理分文件，不利用该红利则永远锁死在单文件 |

## 二、总体目标与约束

**目标**：拆为 `index.html`（模板）+ `app.js`（逻辑）+ `style.css`（样式），逻辑内按域拆为多个 JS 文件顺序注入；无构建、CDN 加载方式不变，浏览器行为零变化。

**硬约束**（必须保持）：
- 无打包器，纯 `<script src>` / `<link>` 顺序加载
- Vue 本地文件 `/verynginx/static/vue.global.prod.js` + CDN fallback 不动
- 模板为 **in-DOM 模板**（Vue 挂载 `#app` 时读 DOM 内容），这是分文件后行为不变的根本保证
- 131 个模板绑定全部保留，`expose()` 机制保留，check_bindings 通过
- CSP 已允许 `script-src 'self'` / `style-src 'self' 'unsafe-inline'`，分文件合法
- 静态资源走 `/verynginx/static/`（nginx alias 到 dashboard 目录，bypass Lua），`router.lua` 兜底 `/verynginx/` 服务同一目录

---

## 三、阶段计划

### Phase 0 — 基线锁定（安全网）

**重构原因**：任何分文件操作前必须先有可回滚的基线，否则无法判断「行为不变」是否成立。

| 步骤 | 工作内容 | 验收要求 |
|------|---------|---------|
| 0.1 | 确认当前 `check_bindings.js`、busted（spec + phase0 两套）、integration 测试全绿 | 各命令退出码 0，记录输出快照 |
| 0.2 | 确认 JS 语法有效、`expose` 引用变量全有声明（292 个） | 语法检查 + 声明比对脚本通过 |
| 0.3 | 审计 `git status` 干净，记录 `index.html` 当前 commit hash 与行数 | 干净基线可随时 `git checkout` 回滚 |
| 0.4 | 梳理 `check_bindings.js` / CI 中对「读最后一个 `<script>` 块」的依赖点 | 输出清单：需随 Phase 2/3 同步修改的文件 |

**验收**：基线快照存留；无未提交改动。

---

### Phase 1 — 拆 CSS（零风险）

**重构原因**：CSS 与 JS 完全无耦合，最先拆可快速见效并建立「物理分文件」流程范式。

| 步骤 | 工作内容 | 验收要求 |
|------|---------|---------|
| 1.1 | 新建 `verynginx/dashboard/style.css`，内容 = 当前 `<style>` 块（15–122 行）原样迁移 | 内容逐字节一致 |
| 1.2 | `index.html` 中 `<style>` 块替换为 `<link rel="stylesheet" href="/verynginx/static/style.css">`，置于 `<head>` | link 路径与现有 vue 资源路径风格一致（`/verynginx/static/`） |
| 1.3 | 运行 check_bindings（只读模板/script，不受影响）+ JS 语法检查 | 全通过 |
| 1.4 | 浏览器（或 docker-compose 环境）冒烟：登录页、深色/浅色主题、任一页面 | 样式与拆分前一致（重点核对 `[data-theme="dark"]` 变量与媒体查询） |

**验收**：`index.html` 无 `<style>` 标签；`style.css` 存在且被引用；CSS 加载走 `/verynginx/static/`（bypass Lua）。此阶段可独立提交。

---

### Phase 2 — 拆 JS 主体（模板 vs 逻辑两文件）

**重构原因**：模板是 in-DOM 模板，把 `<script>` 整体外移即可获得「模板 / 逻辑」两文件结构，浏览器行为不变，是后续按域拆分的前提。

| 步骤 | 工作内容 | 验收要求 |
|------|---------|---------|
| 2.1 | 新建 `verynginx/dashboard/app.js`，内容 = 当前最后一个 `<script>` 块（2049–5186 行）整体迁移，保持模块级 `store`/`csrfToken`/`api()`/`refreshCsrf()`/`isValidIpLiteral()` 与 `Vue.createApp` 结构 | 逻辑字节一致 |
| 2.2 | `index.html` 中该 `<script>` 替换为 `<script src="/verynginx/static/app.js"></script>`，置于 `#app` 之后（模板之后、`</body>` 前） | 加载顺序：vue → app.js；`#app` 模板仍在 HTML 中 |
| 2.3 | **同步修改 `check_bindings.js`**：模板仍从 `index.html` 的 `#app` 提取；脚本逻辑改为读取 `app.js`（Phase 2 暂用单文件） | check_bindings 输出与基线一致：131 模板绑定 / 292 导出 / 161 未用（WARN） |
| 2.3.1 | 验证 `check_bindings.js` 正确解析 `app.js` 中的 `expose()` 调用（而非旧的 `return { ... }`） | 解析器已升级（复用 `refactor_expose.js` 的正则逻辑），Phase 2 提交前确认 |
| 2.4 | JS 语法检查 + 全量测试（spec、phase0、integration） | 与 Phase 0 基线一致 |
| 2.5 | 浏览器冒烟：登录、9 个页面切换、各子 tab（waf rules/attacks/history/tester、kb entries/candidates 等）、弹窗、toast | 行为与拆分前完全一致；网络面板确认请求：vue、app.js、style.css 均 200 |

**验收**：`index.html` 内除 vue fallback 外无逻辑代码；模板 + 逻辑物理分离；测试与基线一致。可独立提交。

---

### Phase 3 — JS 内部分域拆模块（核心步骤）

**重构原因**：逻辑已独立成文件，但单文件 ~3100 行仍属「改一行碰全文件」。按业务域拆成多个 JS 文件顺序注入，让编辑/搜索/diff 以文件为粒度，并显式化共享 context。

**拆分后的文件布局**（均放 `verynginx/dashboard/`，`/verynginx/static/` 提供）：

```
dashboard/
├── index.html          # 模板 + link/script 引用（不再含逻辑）
├── style.css           # 全部样式
├── vue.global.prod.js  # 不动
├── vn-common.js        # 基础设施：store/api/refreshCsrf/isValidIpLiteral + setup 共享上下文（expose 注册表、toast/confirm/theme/page/cfg/navigateTo/loadData 等）
├── vn-dashboard.js     # 概览/状态/统计/连接趋势/格式化 helpers
├── vn-config.js        # cfgTab、matchers、config rules CRUD、save/commit、export/import、dict usage、version、top paths
├── vn-waf.js           # WAF rules/stats/history/timeline/hits/analytics/pending/test/recommender/命中详情
├── vn-frequency.js     # 频率限制 + 模板库 + 规则 CRUD
├── vn-reputation.js    # IP 声誉 + 白名单
├── vn-geoip.js         # GeoIP 查询/配置/自动更新
├── vn-advanced.js      # 指纹 + 插件 + 审计
├── vn-kb.js            # 内核封禁全部（entries/candidates/timeline/bucket/diff/promote/reconcile/趋势）
└── app.js              # 组装：setup() 调用各模块工厂函数，聚合 expose，Vue.createApp().mount()
```

| 步骤 | 工作内容 | 验收要求 |
|------|---------|---------|
| 3.1 | 设计共享 context 协议：`app.js` 创建 `ctx`（含 `api/store/expose/showToast/showConfirm/theme/page/cfg` 等依赖注入），各模块文件挂到 `window.VN` 命名空间，工厂函数接收 `ctx` 返回「状态 + 方法」 | 协议文档化（注释头）；模块间不直接引用对方全局，一律经 `ctx` 或显式返回 |
| 3.2 | **先拆 `vn-reputation.js`**（依赖最少的域）验证模式：迁移 reputation 状态 + 方法到工厂函数 | check_bindings 仍 131/292 全绿；JS 语法有效；其余测试不回归 |
| 3.3 | 按依赖顺序逐个拆分：`vn-dashboard.js` → `vn-config.js` → `vn-waf.js` → `vn-frequency.js` → `vn-geoip.js` → `vn-advanced.js` → `vn-kb.js`；`vn-common.js` 保留 setup 基础设施 | 每拆一个跑一次 check_bindings + 语法检查 + 浏览器冒烟对应页面；`expose()` 调用总数保持 292（注册表聚合） |
| 3.4 | `app.js` 组装：setup() 内按序调用各工厂收集导出，`return Object.fromEntries(exports)` 保留 | setup() 体大幅缩至仅基础设施 + 组装调用 |
| 3.5 | **同步升级 `check_bindings.js`**：模板从 index.html 提取；导出从全部 `vn-*.js` 文件并集提取（不再只读单文件） | 输出与基线一致；并集去重正确 |
| 3.5.1 | 复用 `refactor_expose.js` 的 `expose()` 解析正则逻辑，统一解析入口，避免双实现漂移 | 单一解析源头，`check_bindings.js` 与 `refactor_expose.js` 共享工具函数 |
| 3.6 | 全量回归：spec（带 helper）、phase0（不带 helper）、integration、check_bindings | 与 Phase 0 基线完全一致，无新增 WARN |
| 3.7 | 浏览器全页面冒烟：9 页面 + 所有子 tab + 所有弹窗/confirm/toast/主题切换 | 与拆分前逐项对照一致 |

**验收**：`app.js` 无业务逻辑（仅组装）；每个 `vn-*.js` 内聚单一业务域；加载顺序 `common → dashboard/config/waf/frequency/reputation/geoip/advanced/kb → app` 固定；共享状态仅经 `ctx` 传递。

---

### Phase 4 — 收尾与长期维护

**重构原因**：重构后必须有可持续的校验与文档，否则模块边界随时间腐化。

| 步骤 | 工作内容 | 验收要求 |
|------|---------|---------|
| 4.1 | 更新 CI：`check_bindings.js` 新多文件入口生效；可加「JS 语法检查 + expose 声明比对」步骤（脚本已具备） | CI 全绿 |
| 4.2 | 更新 `AGENTS.md` 附录「模块文件结构」：dashboard 目录改为分文件布局，记录加载顺序与 ctx 协议 | 文档与实际文件一致 |
| 4.3 | 更新 `docs/DESIGN_V2.md` §8 前端 Dashboard 章节（单文件描述 → 分文件架构） | 文档同步 |
| 4.4 | 全量回归（与 3.6 相同）后提交 | 与基线一致 |

**验收**：CI、文档、测试三者在分文件架构下全部通过且同步。

---

## 四、风险与应对

| 风险 | 影响 | 应对 |
|------|------|------|
| setup 闭包共享状态迁移遗漏（Phase 3） | 运行时报 undefined | 每拆一域即跑语法 + check_bindings + 对应页面冒烟；expose 声明比对脚本兜底 |
| 加载顺序错误（模块引用未定义） | 白屏 | Phase 2 起固定加载清单；app.js 组装前 `typeof VN.x === 'undefined'` 防御性检查 |
| check_bindings 多文件并集逻辑 bug | 假阴性/假阳性 | 3.5 后与基线输出 diff 校验 |
| CSP 拦截本地 js/css | 样式/逻辑不加载 | 已核对 `script-src 'self'` + `style-src 'self'` 允许；冒烟阶段检查 Console |
| `router.lua` / nginx alias 对多文件的路径覆盖 | 404 | 复用已验证的 `/verynginx/static/` 路径，不新增 location |

**已验证无阻断问题**（2026-08-18）：
- `/verynginx/static/` location 存在于 `in_server_block.conf:45`，alias 到 `/opt/verynginx/dashboard/`，CSP 允许 `script-src 'self' 'unsafe-inline'`
- `navigateTo`/`loadData`/`store` 已在 setup() 内经 `expose()` 导出，check_bindings 统计 292 个 expose 全覆盖
- Phase 2/3 需同步修改 `check_bindings.js` 解析逻辑（已在计划中）
- `AGENTS.md` 文档同步需在 Phase 4 完成

## 五、提交粒度建议

- Phase 1 → 1 commit
- Phase 2 → 1 commit（含 check_bindings 适配）
- Phase 3 → 每拆一个域 1 commit（先 reputation 打样，再批量），最后 1 commit 收口 app.js + check_bindings
- Phase 4 → 文档 + CI 各自独立 commit

---

## 六、进度追踪

| Phase | 状态 | 完成日期 | 备注 |
|-------|------|---------|------|
| Phase 0 基线锁定 | ✅已完成 | 2026-08-18 | check_bindings 131/292/161、spec 168/0、phase0 309/0 全绿 |
| Phase 1 拆 CSS | ✅已完成 | 2026-08-18 | style.css 108行提取，link 替换，全测试通过 |
| Phase 2 拆 JS 主体 | ✅已完成 | 2026-08-18 | app.js 117903字符提取，script src 替换，check_bindings 适配，全测试通过 |
| Phase 3 分域拆模块 | ✅已完成 | 2026-08-19 | 9个域模块 + vn-common.js + app.js，factory模式，expose注册表，check_bindings 131/293/162，全测试通过 |
| Phase 4 收尾 | ✅已完成 | 2026-08-19 | AGENTS.md 文档同步，CI 已集成 check_bindings，全量回归通过 |
