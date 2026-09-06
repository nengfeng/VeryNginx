# VeryNginx v2 升级指南

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