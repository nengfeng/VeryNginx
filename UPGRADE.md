# VeryNginx v2 升级指南

## v2.3.0 升级要点（2026-10-13）

**无强制配置迁移**——新增配置项均有默认值（运行时自动合并），升级替换代码、重启即生效。本轮 71 个 commit / 64 个文件，要点：

- **请求体检查全面重做（重点）**：`multipart/form-data` 的字段名与字段值进入 WAF 检查（文件内容跳过），并修复 multipart 解析器三处绕过（P0）与参数名漏检；新增 `body.max_field`（字段长度上限，独立于 `max_size`）、`body.scan_exempt`（URI 豁免、大小写不敏感，如 phpMyAdmin）；`body.on_error` 默认改为 `log`，超限 body 只做前缀扫描（ModSecurity ProcessPartial 语义）——大文件上传既不再被整体读入、也不再漏检。
- **默认规则 v9 → v14**：关闭多类扫描器绕过路径、降误报、锚定 phpMyAdmin 豁免、新增 ssrf 类别、收窄敏感文件扩展名、记录堆叠 sqli；`vn_scanner_0014` 修复为命中 ffuf 真实默认 UA（"Fuzz Faster U Fool"——旧正则从未命中过任何一次 ffuf）；`vn_rce_0007` 修复普通文本误报（命令后要求路径/参数形态，`; cat is a pet`、`wait; curl the docs` 不再 403）；14 条参数规则的管理路径豁免支持 `.php`（`/adminer.php`、`/phpminiadmin.php` 的合法 SQL 不再被拦，嵌套路径见下方「配置指引」）；`vn_spam_0019` 描述与 log 动作对齐；新增出厂规则正/负样本电池 `test/v2/factory_rules_battery.py` 作为常驻门禁。`waf-rules.json` 是运行态文件、升级不覆盖：**升级后面板「规则与出厂差异」会列出漂移，可按需「同步出厂内容」**（历史命中计数保留）。
- **IP 声誉增强**：被标记 IP 现带原因、可下钻查看扣分记录与 IP 信息（可选 GeoIP 质量 enrichment + ipinfo 回源）；新增按日持久的「今日被标记 IP（含已过期）」记录（保留 48h；写路径封顶——最多保留最新 100 条，`flagged_today` 计数器精确不封顶）。
- **每主机请求统计**：面板新增主机过滤。
- **面板**：历史 tab 以撤销语义重做（回滚可再撤销、删除可按条恢复）；出厂漂移提示按 action 类型解释（灰度 log 与 block 一目了然），详情可逐条「接受出厂动作」拉齐陈旧动作（灰度状态默认保留、按条显式接受）；restore-defaults 只按 id 补回缺失的出厂规则、不覆盖操作动作；登录表单、模态布局与静态资源缓存标签修复。
- **GeoIP**：`validate_mmdb` 恒失败修复、镜像下载跟随重定向并报告全部镜像失败。
- **供应商**：lua-resty-http 0.17.2 → 0.18.0。
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