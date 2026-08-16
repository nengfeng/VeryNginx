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

```bash
# 登录 VPS
ssh user@your-vps

# 下载并运行升级脚本
curl -sSL https://raw.githubusercontent.com/nengfeng/VeryNginx/v2/tools/upgrade.sh | sudo bash

# 重启
sudo systemctl restart openresty
```

脚本自动处理：备份配置 → 拉取代码 → 替换 → 恢复配置 → 安装依赖。

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
# 拉取最新代码
cd /tmp
git clone --depth 1 --branch v2 https://github.com/nengfeng/VeryNginx.git
cd VeryNginx

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