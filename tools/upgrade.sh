#!/bin/bash
# -*- coding: utf-8 -*-
# VeryNginx v2 升级脚本 — 保留用户配置，替换代码
# 用法: bash upgrade.sh [安装目录]
# 默认安装目录: /opt/verynginx

set -euo pipefail

VN_DIR="${1:-/opt/verynginx}"
BACKUP_DIR="${VN_DIR}/.upgrade_backup_$(date +%Y%m%d_%H%M%S)"
GIT_CLONE_DIR="/tmp/verynginx_upgrade_$$"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---- 检查依赖 ----
info "=== Step 0: 检查依赖 ==="

# 检查 git
if ! command -v git &>/dev/null; then
    error "git 未安装，请先安装: apt install -y git"
    exit 1
fi

# 检查 libmaxminddb
if ldconfig -p 2>/dev/null | grep -q libmaxminddb; then
    info "libmaxminddb 已安装"
else
    warn "libmaxminddb 未安装，正在安装..."
    apt update -qq && apt install -y -qq libmaxminddb-dev
    info "libmaxminddb 安装完成"
fi

# ---- 检查现有安装 ----
info "=== Step 1: 检查现有安装 ==="
if [ ! -d "${VN_DIR}" ]; then
    error "未找到安装目录: ${VN_DIR}"
    echo "   请先运行安装脚本或指定正确的路径"
    exit 1
fi

if [ ! -f "${VN_DIR}/configs/config.json" ] && [ ! -f "${VN_DIR}/verynginx/configs/config.json" ]; then
    warn "未找到 config.json，可能尚未配置"
else
    info "找到现有配置"
fi

# ---- 备份 ----
info "=== Step 2: 备份用户数据 ==="
mkdir -p "${BACKUP_DIR}"

# 备份 configs 目录
if [ -d "${VN_DIR}/configs" ]; then
    cp -r "${VN_DIR}/configs" "${BACKUP_DIR}/configs"
    info "备份 configs/ -> ${BACKUP_DIR}/configs"
fi

# 备份 verynginx/configs 目录（新版本路径）
if [ -d "${VN_DIR}/verynginx/configs" ]; then
    cp -r "${VN_DIR}/verynginx/configs" "${BACKUP_DIR}/verynginx_configs"
    info "备份 verynginx/configs/ -> ${BACKUP_DIR}/verynginx_configs"
fi

# 备份 GeoIP 数据库
if [ -f "${VN_DIR}/geoip/GeoLite2-City.mmdb" ]; then
    mkdir -p "${BACKUP_DIR}/geoip"
    cp "${VN_DIR}/geoip/GeoLite2-City.mmdb" "${BACKUP_DIR}/geoip/"
    info "备份 GeoIP 数据库"
fi

info "备份完成于: ${BACKUP_DIR}"

# ---- 拉取最新代码 ----
info "=== Step 3: 拉取最新代码 ==="
git clone --depth 1 --branch v2 \
    "https://github.com/nengfeng/VeryNginx.git" \
    "${GIT_CLONE_DIR}" 2>&1 || {
    error "克隆失败，请检查网络或 GitHub 访问"
    rm -rf "${GIT_CLONE_DIR}"
    exit 1
}
info "代码拉取完成 (commit: $(cd ${GIT_CLONE_DIR} && git rev-parse --short HEAD))"

# ---- 替换代码 ----
info "=== Step 4: 替换代码目录 ==="

# 检查 nginx_conf 中是否包含对 in_http_block.conf 的引用
OLD_NGINX_CONF="${VN_DIR}/nginx.conf"
if [ -f "${OLD_NGINX_CONF}" ]; then
    if grep -q "in_http_block" "${OLD_NGINX_CONF}" 2>/dev/null; then
        info "nginx.conf 已包含 in_http_block.conf"
    else
        warn "nginx.conf 未包含 in_http_block.conf，请手动在 http {} 块中添加:"
        warn "    include /opt/verynginx/verynginx/nginx_conf/in_http_block.conf;"
        warn "省略此步骤将导致 Lua 路径未设置，OpenResty 无法启动"
    fi
fi

# 替换 verynginx 目录（保留配置）
if [ -d "${VN_DIR}/verynginx" ]; then
    rm -rf "${VN_DIR}/verynginx.old" 2>/dev/null || true
    mv "${VN_DIR}/verynginx" "${VN_DIR}/verynginx.old"
    info "旧代码移出: ${VN_DIR}/verynginx.old"
fi

cp -r "${GIT_CLONE_DIR}/verynginx" "${VN_DIR}/verynginx"
info "新代码部署到 ${VN_DIR}/verynginx"

# 复制 nginx_conf 到安装目录顶层（兼容旧引用方式）
if [ -d "${VN_DIR}/verynginx/nginx_conf" ]; then
    cp -r "${VN_DIR}/verynginx/nginx_conf" "${VN_DIR}/nginx_conf"
    info "同步 nginx_conf -> ${VN_DIR}/nginx_conf"
fi

# ---- 恢复配置 ----
info "=== Step 5: 恢复用户配置 ==="

# 恢复 config.json（优先从备份取）
if [ -f "${BACKUP_DIR}/configs/config.json" ]; then
    cp "${BACKUP_DIR}/configs/config.json" "${VN_DIR}/verynginx/configs/config.json"
    info "恢复 config.json"
elif [ -f "${BACKUP_DIR}/verynginx_configs/config.json" ]; then
    cp "${BACKUP_DIR}/verynginx_configs/config.json" "${VN_DIR}/verynginx/configs/config.json"
    info "恢复 config.json (从子目录备份)"
fi

# 恢复 waf-rules.json
if [ -f "${BACKUP_DIR}/configs/waf-rules.json" ]; then
    cp "${BACKUP_DIR}/configs/waf-rules.json" "${VN_DIR}/verynginx/configs/waf-rules.json"
    info "恢复 waf-rules.json"
elif [ -f "${BACKUP_DIR}/verynginx_configs/waf-rules.json" ]; then
    cp "${BACKUP_DIR}/verynginx_configs/waf-rules.json" "${VN_DIR}/verynginx/configs/waf-rules.json"
    info "恢复 waf-rules.json (从子目录备份)"
fi

# 确保 GeoIP 数据库链接
if [ -f "${BACKUP_DIR}/geoip/GeoLite2-City.mmdb" ]; then
    mkdir -p "${VN_DIR}/geoip"
    cp "${BACKUP_DIR}/geoip/GeoLite2-City.mmdb" "${VN_DIR}/geoip/"
    info "恢复 GeoIP 数据库"
fi

# ---- 清理 ----
info "=== Step 6: 清理 ==="
rm -rf "${GIT_CLONE_DIR}"
rm -rf "${VN_DIR}/verynginx.old"
info "临时文件已清理"

# ---- 完成 ----
echo ""
info "╔══════════════════════════════════════════════════════════╗"
info "║  升级完成！                                           ║"
info "╠══════════════════════════════════════════════════════════╣"
info "║  安装目录: ${VN_DIR}           ║"
info "║  备份目录: ${BACKUP_DIR}     ║"
info "╠══════════════════════════════════════════════════════════╣"
info "║  下一步: 重启 OpenResty                                ║"
info "║                                                         ║"
info "║  sudo systemctl restart openresty                        ║"
info "╠══════════════════════════════════════════════════════════╣"
info "║  如果启动失败，查看日志:                                 ║"
info "║  sudo journalctl -u openresty -n 50                      ║"
info "║  sudo tail -30 /var/log/openresty/error.log              ║"
info "╚══════════════════════════════════════════════════════════╝"