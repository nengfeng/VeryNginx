# VeryNginx v2 升级指南

## v2.3.0 升级要点（2026-10-13）

**无强制配置迁移**——新增配置项均有默认值（运行时自动合并），升级替换代码、重启即生效。本轮 109 个 commit / 90 个文件，要点：

- **请求体检查全面重做（重点）**：`multipart/form-data` 的字段名与字段值进入 WAF 检查（文件内容跳过），并修复 multipart 解析器三处绕过（P0）与参数名漏检；新增 `body.max_field`（字段长度上限，独立于 `max_size`）、`body.scan_exempt`（URI 豁免、大小写不敏感，如 phpMyAdmin）；`body.on_error` 默认改为 `log`，超限 body 只做前缀扫描（ModSecurity ProcessPartial 语义）——大文件上传既不再被整体读入、也不再漏检。
- **默认规则 v9 → v17**：关闭多类扫描器绕过路径、降误报、锚定 phpMyAdmin 豁免、新增 ssrf 类别、收窄敏感文件扩展名、记录堆叠 sqli；`vn_scanner_0014` 修复为命中 ffuf 真实默认 UA（"Fuzz Faster U Fool"——旧正则从未命中过任何一次 ffuf）；`vn_sqli_0001/0002/0004` 补齐绕过类（`UNION(SELECT`、`UNION DISTINCT`、注释混淆、`LIKE/IN/BETWEEN`、无前缀 `sleep`、`CHAR()` 构造）并豁免教程散文；`vn_xss_0005` 补全事件表（pointer/animation/transition/form 家族与注释分隔），`vn_xss_0006` 改为 scheme+代码形态门（`Function/setTimeout/fetch` 进、`confirm your email` 出）并覆盖 `data:text/html`；`vn_ssrf_0021` 覆盖 `user@` 前缀；`vn_rce_0007` 经三轮外部复评后定型为值锚定 block（分隔符必须出现在参数值开头，高危裸调用命令无参数约束；data-URI/CSV 的分隔符全在值中部，天然豁免），宽命令表与裸侦察命令落入 log-only 伴随规则 `vn_rce_0025`（非锚定宽扫，`go; rm -rf /` 照样记录），两层均不含任何字节内容守卫（"值内无非 ASCII"曾是万能绕过开关：追加一个高位字节即清零检测，已删除并用结构断言禁用）；14 条参数规则的管理路径豁免支持 `.php`（`/adminer.php`、`/phpminiadmin.php` 的合法 SQL 不再被拦，嵌套路径见下方「配置指引」）；`vn_spam_0019` 描述与 log 动作对齐；新增出厂规则正/负样本回归测试集 `test/v2/factory_rules_battery.py`（312 项，逐命令族覆盖散文/攻击样本，真机 PCRE 双引擎对照）作为常驻门禁。`waf-rules.json` 是运行态文件、升级不覆盖：**升级后面板「规则与出厂差异」会列出漂移，可按需「同步出厂内容」**（历史命中计数保留）。**v18 → v19（两轮对抗复审，均经真机 PCRE 双引擎复核后才改）**：`vn_sqli_0001` 的 UNION/SELECT 分隔符扩展到 SQL 注释（`/*x*/` 任意注释体、`--` 与 `#` 两种行注释，且保留「半开」形态以免把 `/*!50000SELECT*/` 里的 SELECT 吞掉——那正是 v16 的修法），`vn_sqli_0002` 的比较间隙同步容忍行注释（`' OR-- -\n1=1-- -` 此前穿过 block 规则），新增 log 级 `vn_sqli_0005` 捕获字符串逃逸后的堆叠查询（`1'; SELECT password FROM users`，旧规则四条全清）；`vn_xss_0006` 修复一处**可达性回归**：v16 把代码形态分支放在零宽前瞻之后并钉死在冒号后第一个字符，于是 `javascript: alert(1)`（一个空格）、`javascript:globalThis.alert(1)`、`javascript:atob(...)()`、`javascript:(alert(1))`、裸 base64 的 `data:text/html` 全部漏报（实测攻击集 13/24），v16 换来的精度其实是「分支不可达」的副产品而非设计，现按「标识符链 + `(`/`[`/`=`/反引号」判定（24/26，既有钉 0 违反，代价是两条引用代码的技术帖散文命中）；`vn_rce_0007`/`vn_rce_0025` 分隔符补上 `&`、`&&`、`||`（`&&rm -rf /`、`&&cat /etc/passwd` 此前两档全过），且英文填充词守卫按「命令名是否与英文词冲突」拆分——`mkfs/crontab/nohup/pkill/base64/openssl` 取消守卫（此前插入一个 `the` 即可清空 `;mkfs the /dev/sda`），保留守卫的命令残余漏报已在回归测试集中显式断言；`vn_xss_0005` 事件表 92 → 116（`onpageshow`/`onhashchange`/`onmessage`/`onoffline`/`onunload`/`onstorage` 等现役 content attribute 此前缺失）；`vn_xss_0004` 补 URI 分支（此前只查参数，`GET /<script>alert(1)</script>` 完全不经评估）；`vn_rce_0009` 改为「scheme 后必须跟带点主机名」的正向约束并覆盖 `jar:http://host/x.jar!/`。回归测试集从 312 项扩到 **477** 项：`vn_xss_0004`/`vn_rce_0008`/`vn_rce_0009` 此前**零行为断言**（只有「能编译」检查，任何误改都是静默的），现已补齐正负样本；v17 的结构断言只认一种字面形态所以没看见填充词守卫，现改为扫描全部负向前瞻 + 白名单并附理由——**断言比单条正则更重要，它已经为两个版本背书过「守卫」是干净的**。
- **频率限制：从模板创建的规则此前从未生效（升级前必读的行为变更）**：面板与模板库把匹配器存为 `matcherJson`（JSON 字符串），而配置编译（`compile_runtime_snapshot`）、配置校验（`validate_rule`）与 `matcher.resolve()` **全都只消费 `rule.matcher`**；插件拿到 nil 匹配器后走 `if not matcher_def then goto continue end` —— **静默跳过、不打任何日志**，面板却照常把该规则显示为「已配置」。产线实测：一条以模板方式下发（2 次/60 秒、精确 URI 匹配）的规则连打 5 次零拦截；同一规则改用 `matcher` 下发，第 3 次即 429。也就是说，**任何通过「应用模板」创建的限流规则都从未拦截过任何请求**（频率规则编辑器、以及 WAF/配置规则编辑器本来就发 `matcher`，只有模板这条路径是坏的）。**升级后这些规则会立即开始执行。** 若站点上已有从模板创建的限流规则、尤其是空匹配器的全局兜底，**请在升级前核对阈值**：实测跨全部受 WAF 保护站点的真实访客单 IP 每分钟峰值约 260–268，若全局规则阈值是 300/分钟，余量不足 12%，一次页面批量加载即可能被拦。修复三处：加载与 `atomic_mutate` 两条路径都在**校验之前**展开 `matcherJson`（顺序是关键——校验才是拦截畸形 IP / CIDR 的那道闸，后展开等于留后门）；`frequency_templates.apply()` 直接物化 matcher，畸形覆盖值报错而不是再产出一条死规则；插件在匹配器解析不出时按「规则 ID + 配置代次」告警一次（置于请求路径，故必须去重以免淹掉错误日志；配置一改仍会对新坏规则再报一次）。**连带修正的两个缺陷**：①「全局 CC 防护」「爬虫 / 扫描」两个模板出厂 `code = 200`，而 block 动作返回 200 会被客户端、访问日志、面板拦截率与前置 CDN 全部读成成功（缓存甚至可能存储并重放该响应），且其描述承诺的「JS 人机验证」永远不会发生——插件硬编码 `action = "block"`，challenge 分支只在 action 类型为 `challenge` 时才走到；200 也不是「请求挑战」的方式（challenge 分支自身就是 `ngx.exit(200)`，因为验证页必须 200 才能跑脚本）。两模板已改 429 并更正描述，`rule_engine` 另加一道保险：block 拒绝 2xx（记 WARN 并回落 403），使这类缺陷无法通过手填响应码复发。② 插件的 response 兜底传的是人话 `"Too Many Requests"`，而 `action/response.lua` 期望的是**已注册模板名**，全库只注册了 `forbidden_json`，因此**所有 block 型限流规则返回的正文都是内部错误串 `response template not found`**（已注册 `too_many_requests`：429 + `Retry-After: 60` + 可读正文，并让 `response.resolve()` 透传可选 `headers`）。**第三处：同维度规则的计数器互相污染（升级后新增同类规则前必读）**——v1 计数键原本是 `fl:<维度>:<值>`、**不含 rule id**，而插件对每条命中的规则都会 `incr` 一次，于是两条按 IP 计数的规则共用同一个数字：实测 30 个请求把计数推到 56（每请求计两次、阈值实际打对折），且键的 TTL 由先创建者决定——1 秒的突发窗口被 60 秒规则的 TTL 覆盖，「50 次/1 秒」实际变成「50 次/60 秒锁死一分钟」，正常浏览在突发过后仍被 429 拦一分钟。`build_key()` 现接受可选 `rule_id`，请求路径一律按规则隔离（旧调用与既有测试的键形状不变）。**另外：`v2` 计数命名空间从未启用过**——插件的 `is_v2_active()` 要求 `fl:v2:cutover_epoch` 已存在，而唯一会写它的 `core/frequency.is_cutover_complete()` 只被 `kernel_blocking/readiness.lua` 调用，插件从不调用，因此无法自举。**未在本次修复中接上**：一旦启用 v2 会连带激活 CC 违规证据记录，而那条链路会升级成真实的内核级防火墙封禁，不应藏在一个键格式修复里，需要单独评估。v1 + 按规则隔离的键在当前语义下已经正确。
- **Cloudflare 真实客户端 IP（升级后务必核对，重要行为变更）**：`nginx_conf/cf-real-ip.conf` 原先只认 `CF-Connecting-IP`，而**这个头并非总是存在**——某些 zone（尤其是流量经 Cloudflare 二次转发、或被 Origin Rule 去掉该头的配置）只下发 `X-Forwarded-For`；而 `real_ip_header` 在指定头缺失时**静默不生效**，于是 `$remote_addr` 一直保持 Cloudflare 边缘节点地址、无任何报错。实测：某站 306 万行访问日志 **100% 记的是边缘 IP、零真实客户端**，其余 Cloudflare 代理站却全部正常——差异只在这个头上。后果不是观感问题：IP 声誉给共享地址打分、内核封禁可能一封封掉身后成千上万用户、per-IP 限流把一个边缘节点上的所有访客并进同一个桶。现在改为读取 `X-Forwarded-For` 并开启 `real_ip_recursive`（Cloudflare 必定下发该头）：从右往左跳过受信 CF 网段、取第一个非信任地址，即 CF-Connecting-IP 本该给出的值；客户端伪造自己的 XFF 也拿不到最终结果，因为伪造项位于 Cloudflare 追加项的左侧。**升级后请抽查日志**：`awk '{print $1}' /data/wwwlogs/<站点>_nginx.log | sort -u | head`，若出现 `104.x`/`172.6x-7x.x`/`162.15x.x`/`108.162.x` 等边缘地址即为未生效。注意：修复前产生的历史日志无法回溯还原真实 IP（当时只记下了边缘地址）。
- **IP 声誉增强**：被标记 IP 现带原因、可下钻查看扣分记录与 IP 信息（可选 GeoIP 质量 enrichment + ipinfo 回源）；新增按日持久的「今日被标记 IP（含已过期）」记录（保留 48h；写路径封顶——最多保留最新 100 条，`flagged_today` 计数器精确不封顶）。
- **每主机请求统计**：面板新增主机过滤。
- **面板**：历史 tab 以撤销语义重做（回滚可再撤销、删除可按条恢复）；出厂漂移提示按 action 类型解释（灰度 log 与 block 一目了然），详情可逐条「接受出厂动作」拉齐陈旧动作（灰度状态默认保留、按条显式接受）；restore-defaults 只按 id 补回缺失的出厂规则、不覆盖操作动作；登录表单、模态布局与静态资源缓存标签修复。
- **GeoIP**：`validate_mmdb` 恒失败修复、镜像下载跟随重定向并报告全部镜像失败。
- **TLS 指纹改用 JA4，并修复两条「执法链出厂即死」的缺陷**：原实现读 `$ssl_client_j3_hash`（LNMP 的 vanilla nginx 未编译该模块，恒为 nil）且 filter 插件读一个**全仓无人写入**的 `ctx.request.ja3_fingerprint`，因此指纹封禁/挑战与跨 IP 关联告警从未真正生效。现在改为在 TLS 握手期（`ssl_client_hello_by_lua_block`，唯一能看到原始 ClientHello 的阶段）计算 **JA4**——排序后的密码套件/扩展使其对 GREASE 随机化免疫；无需重编 nginx（本机 lua-nginx-module 0.10.32 已提供全部所需接口）。指纹库条目新增 **kind（ja3/ja4/ja4h）与 match_mode（exact/family）**，匹配按 kind 分空间，`tls:`（协商套件串）显式不可匹配；**family 匹配**取人可读的 section A（JA4 前 10 字符 / JA4H 前 12），客户端换套件仍能按家族追踪。**升级需注意（重要）**：钩子必须挂在 **server 级**，且**同一监听端口上的每个 SSL server 块都要有**。lua-nginx-module 按 listen socket 安装 client-hello 回调——只要该端口上任一 server 定义了 `ssl_client_hello_by_lua_block`，**其余未定义的 server 会在 TLS 握手阶段被中止**（日志 `no ssl_client_hello_by_lua* defined in server X`，alert 级），用户侧表现为 **Cloudflare 525 / `tlsv1 alert internal error`**，且影响面是同端口的所有非托管站点。`upgrade.sh` 与安装器已按「有 `ssl_certificate` 即注入」自动处理；手动部署请确认每个 SSL server 都有 `include /opt/verynginx/nginx_conf/tls-fingerprint.conf;`，并以**全站 TLS 冒烟**（逐域握手，而非只测装了 WAF 的那几个）收尾。另注意两点：① 钩子自身做了降级保护（`require` 也包在 pcall 里），即使 Lua 模块加载失败或 JA4 计算出错也只是「本次没有 JA4」，**不会影响握手**；② LNMP 的 `error_log` 指向 `/data/wwwlogs/`，排查线上问题不要只看 `/usr/local/nginx/logs/`。`inject_tls_fingerprint.py --check` 为只读审计模式，会列出每个 SSL server 及其钩子状态、有缺失即退出码非 0——**每次新增域名/站点后跑一次**，比事后从 525 里反查便宜得多。已内置该注入逻辑的 LNMP（`vhost.sh` 会在生成 vhost 时追加钩子）无需手工处理。面板支持按类型/匹配方式维护条目；官方映射表可用 `tools/import_ja4db.py` 导入候选（**默认 log**，良性/威胁共享的哈希整条跳过；自签证书或按 IP 访问面板时用 `--ca` / `--insecure`，默认仍严格校验证书）。JA4H（HTTP 层指纹）默认关闭：JA4 本体为 BSD-3，JA4H 属 JA4+（FoxIO License 1.1），随产品分发需先确认许可（`fingerprints.ja4.http_enable`）。
- **供应商**：lua-resty-http 0.17.2 → 0.18.0；新增 vendor `lua-resty-ja4` v0.2.0（MIT）。
- **安装/升级**：升级保留运行时配置与状态（`configs/` 除两个默认模板外不再被覆盖）；测试 helper 不再解析到生产树。

### Cloudflare CDN 真实客户端 IP

站点经 Cloudflare 回源时，源站看到的是 CF 边缘 IP——WAF 命中记录、IP 声誉评分、内核封禁、登录限流都会记在“一个边缘 IP 背后成千真实用户”的粒度上（归因错位、评分失真，误封一个边缘 IP 会伤及其后全部真实用户）。v2.3.0 起用 http_realip_module 把 `remote_addr` 还原为真实客户端 IP，配置集中在 `nginx_conf/cf-real-ip.conf` 一处：

- **新装**：两条安装路径自动带上——OpenResty 模板经 `in_http_block.conf` 的 include；lnmp 安装器向 `nginx.conf` 注入同一行 include（幂等：检测到已有 `set_real_ip_from` / `real_ip_header` / 本 include 会跳过，不覆盖运维自定义的 realip 配置）。
- **升级（OpenResty 安装）**：`upgrade.sh` 会更新 `in_http_block.conf`，升级后自动生效，无需操作。
- **升级（lnmp 安装）**：`upgrade.sh` 不修改 lnmp 的 nginx.conf，需手动在 `http {}` 块加一行：
  `include /opt/verynginx/nginx_conf/cf-real-ip.conf;`
- **区间维护**：只维护 `verynginx/nginx_conf/cf-real-ip.conf` 一处，季度核对官方列表（https://www.cloudflare.com/ips-v4 与 ips-v6）。
- **安全性**：仅对来自 CF 官方区间的连接替换 IP，直连源站伪造 `CF-Connecting-IP` 无效；站点不在 CF 后面时该配置为无副作用的空操作。

---

## 配置指引：phpMyAdmin / adminer 部署在非标准路径

参数注入类规则（14 条 sqli/xss/rce/lfi/ssrf/穿越）带 URI 豁免，只认**根路径** `/(phpmyadmin|phpminiadmin|adminer)`（工厂规则 v14 起含 `.php` 形式，如 `/adminer.php`、`/phpminiadmin.php`）。豁免刻意不放开任意嵌套路径——否则攻击者只要在路径里嵌一段 `phpmyadmin` 就能绕过全部参数检查。

部署在更深层路径（如 `/mysql/phpmyadmin/`、`/tools/adminer.php`）时规则豁免不命中，管理工具里合法的 SQL 可能被 `vn_sqli_*` 拦下，需要补配 `body.scan_exempt`：

- **含义**：URI 前缀数组，大小写不敏感、边界感知（`/phpMyAdminEvil` 蹭不到 `/phpMyAdmin` 的豁免）。命中的请求**完全不读、不扫描请求体**，导入/查询提交不再被参数规则拦截。
- **示例**：`"scan_exempt": ["/phpMyAdmin", "/mysql/phpmyadmin/"]`
- **边界**：只豁免请求体；URL query 参数仍在扫描范围内（管理工具的 SQL 都在 POST body，通常足够）。
- **生效**：面板「配置」保存即热生效（各 worker 数秒内收敛）；手改 `configs/config.json` 后需 `nginx -s reload`。
- 出厂默认 `[]` 是有意的：豁免记录的是运维对自己站点 URI 的判断，不应由上游替你开。

---

## v2.2.1 升级要点（2026-09-06）

v2.2.1 是 v2.2 的修复版本，**无配置迁移**，升级后重启即生效。主要内容：

- **GeoIP 全面修复（重点）**：修复「检查更新」永远失败的根因——默认 CDN 源指向一个从上线起就 404 的地址，且旧逻辑会让一个坏地址屏蔽全部内置镜像；下载的数据库现在先经 libmaxminddb 探测确认可打开再落盘，失败自动回滚并逐镜像尝试；修复 FFI 加载层三处缺陷（参数错位/变量解包/模块导出位置）。**升级后请在面板再点一次「检查更新」以下载可用数据库**，之后 IP 查询即恢复。
- **webhook URL 校验修复**：修复半成品的 DNS 校验重构——此前任何带 webhook 地址的 `POST /config` 都会 500，且 https-only/IPv6 括号/私网字面量校验整体缺失；发送时的 DNS 校验此前从未真正执行（补上 timer phase）。
- **面板**：WAF 头部「刷新 / + 新建规则」按钮与标题对齐；GeoIP 更新不再需要输入 UPDATE 确认（更新已无破坏性）。
- luacheck 全绿（51 文件零警告）。

**从 v2.2 升级**：升级锚固定在 v2.2 的内容版本，前进到 v2.2.1 需显式指定一次：

```bash
sudo VN_UPGRADE_COMMIT=<v2.2.1 的升级锚 commit> /opt/verynginx/tools/upgrade.sh
```

（锚 commit 见本版本 release 说明；之后部署的脚本即携带新锚，下次升级无需覆盖。）

---

## v2.1 升级要点

- **Schema 版本保持 2.0** — 无需手动修改 `config.json` 中的 `version` 字段
- **共享字典新增**：`metrics_labeled`（Prometheus 高基数指标隔离，16m），需在 `nginx.conf` 的 `http {}` 块内声明：
  ```nginx
  lua_shared_dict metrics_labeled 16m;
  ```
  自动升级脚本已处理；手动升级请检查 `in_http_block.conf` 是否已包含。
- **频率限制规则 CIDR 不再接受** — 规则 `matcher` 中的 IP 值若含 `/`（如 `10.0.0.0/8`）会被拒绝，请改为单 IP 或正则
- **白名单条目格式校验** — `ip_reputation.whitelist` 保存时校验每条 IP/CIDR，非法条目会阻止保存
- **session_secret 保护** — `/config` 与 `/config/export` 已脱敏；升级后首次保存配置会自动恢复真实密钥（从内存读取），无需手动操作
- **GeoIP 目录权限** — 已修正为 755 + `chown nginx_user`，手动升级请确认 `/opt/verynginx/geoip` 权限

## 自动升级（推荐）

**信任模型（先读这段）**：升级的信任锚是**安装时部署在本机的脚本副本**
`/opt/verynginx/tools/upgrade.sh`——它的 `VN_PINNED_COMMIT` 在安装时被烘焙为
当次安装对应的 commit，升级时按它 checkout，仓库分支被改写也影响不到这个锚。

**禁止 `curl … | bash` 从分支上取脚本运行**：那样脚本（连同其中的 pin）
就落在改写分支的人手里，等于没有 pin。

```bash
# 登录 VPS
ssh user@your-vps

# 运行【本机已部署】的升级脚本（不要从网上下载脚本本体）
sudo /opt/verynginx/tools/upgrade.sh

# 重启
sudo systemctl restart openresty
```

脚本自动处理：备份配置 → 按 pin checkout 代码 → 替换 → 恢复配置 → 安装依赖，
并报告所用 commit 落后 v2 分支多少个提交。

**升级到更新的版本**：pin 是刻意固定的——前进需要显式的信任决定。查 release
说明确认目标 commit 后：

```bash
sudo VN_UPGRADE_COMMIT=<release 说明中的 commit> /opt/verynginx/tools/upgrade.sh
```

脚本会大声警告此次覆盖；升级部署的新代码会携带新锚供下次使用。

**初始安装后的首次升级**：安装器（install.py / install-lnmp.sh）会把
`tools/upgrade.sh` 连同安装时 commit 一起部署到 `/opt/verynginx/tools/`；
旧版安装（无该文件）请先手动补一次：从 release 说明核对脚本内容后再放入。

## 手动升级

如果自动脚本不适用，可按以下步骤操作。

### 1. 备份

```bash
# 保存你的配置和规则
cp /opt/verynginx/configs/config.json ~/config.json.bak
cp /opt/verynginx/configs/waf-rules.json ~/waf-rules.json.bak
cp -r /opt/verynginx/configs/rule_history ~/rule_history.bak 2>/dev/null || true
```

### 2. 部署新代码

```bash
# 拉取代码并固定到 release 说明确认的 commit（不要浮动在分支上）
cd /tmp
git clone https://github.com/nengfeng/VeryNginx.git
cd VeryNginx
git checkout <release 说明中的 commit>

# 替换核心代码
sudo rm -rf /opt/verynginx/verynginx/core
sudo rm -rf /opt/verynginx/verynginx/api
sudo rm -rf /opt/verynginx/verynginx/plugin
sudo rm -rf /opt/verynginx/verynginx/matcher
sudo rm -rf /opt/verynginx/verynginx/dashboard
sudo rm -rf /opt/verynginx/verynginx/nginx_conf
sudo rm -rf /opt/verynginx/verynginx/resty

sudo cp -r verynginx/core       /opt/verynginx/verynginx/core
sudo cp -r verynginx/api        /opt/verynginx/verynginx/api
sudo cp -r verynginx/plugin     /opt/verynginx/verynginx/plugin
sudo cp -r verynginx/matcher    /opt/verynginx/verynginx/matcher
sudo cp -r verynginx/dashboard  /opt/verynginx/verynginx/dashboard
sudo cp -r verynginx/nginx_conf /opt/verynginx/verynginx/nginx_conf
sudo cp -r verynginx/resty      /opt/verynginx/verynginx/resty

# 替换入口文件
sudo cp verynginx/on_rewrite.lua        /opt/verynginx/verynginx/on_rewrite.lua
sudo cp verynginx/on_access.lua         /opt/verynginx/verynginx/on_access.lua
sudo cp verynginx/on_log.lua            /opt/verynginx/verynginx/on_log.lua
sudo cp verynginx/waf-rule-manager.lua  /opt/verynginx/verynginx/waf-rule-manager.lua
```

### 3. 恢复配置

```bash
# 恢复你的配置文件（不会丢失数据）
sudo cp ~/config.json.bak     /opt/verynginx/configs/config.json
sudo cp ~/waf-rules.json.bak  /opt/verynginx/configs/waf-rules.json
```

### 4. 重启

```bash
# 验证配置
sudo nginx -t

# 重启
sudo systemctl restart openresty

# 查看日志
sudo journalctl -u openresty -n 50 --no-pager
```

## 检查升级成功

访问 Dashboard：`http://your-vps-ip/verynginx/`，登录后检查：

1. WAF 规则列表是否显示原有规则
2. Dashboard 版本信息是否更新
3. GeoIP 查询是否正常

## 升级后故障排查

| 症状 | 原因 | 解决 |
|------|------|------|
| OpenResty 无法启动 | `lua_package_path` 未正确配置 | 升级脚本已自动修补 nginx.conf；若手动升级，检查 `in_http_block.conf` 是否被 include |
| GeoIP 查询返回空 | `lua-resty-maxminddb` 未安装 | `apt install libmaxminddb-dev` |
| Dashboard 白页 | 新版 Dashboard 需要 Vue 3 | 刷新浏览器缓存（Ctrl+F5） |
| 配置丢失 | config.json 路径变化 | 从 `~/config.json.bak` 恢复 |