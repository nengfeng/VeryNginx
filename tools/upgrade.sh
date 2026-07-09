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

cleanup() {
    rm -rf "${GIT_CLONE_DIR}" "${VN_DIR}/.verynginx_new" 2>/dev/null || true
}
trap cleanup EXIT

# ---- 检查依赖 ----
info "=== Step 0: 检查依赖 ==="

if ! command -v git &>/dev/null; then
    error "git 未安装，请先安装: apt install -y git"
    exit 1
fi

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

if [ ! -f "${VN_DIR}/configs/config.json" ]; then
    warn "未找到 config.json，可能尚未配置"
else
    info "找到现有配置"
fi

# ---- 备份 ----
info "=== Step 2: 备份用户数据 ==="
mkdir -p "${BACKUP_DIR}"

if [ -d "${VN_DIR}/configs" ]; then
    cp -r "${VN_DIR}/configs" "${BACKUP_DIR}/configs"
    info "备份 configs/ -> ${BACKUP_DIR}/configs"
else
    warn "未找到 configs/ 目录，无配置可备份"
fi

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

# ---- 部署新代码（覆盖式，不影响 openresty/ 和 configs/ 中的用户数据） ----
info "=== Step 4: 部署新代码 ==="

if [ ! -d "${VN_DIR}/core" ]; then
    error "未找到 ${VN_DIR}/core/，安装目录结构异常"
    exit 1
fi

# 覆盖部署：cp -r -f 将新代码铺到 VN_DIR/，不影响 openresty/
# configs/ 中的用户数据（config.json/waf-rules.json 等）不在 git 仓库中，不会被覆盖
cp -r -f "${GIT_CLONE_DIR}/verynginx/." "${VN_DIR}/"
info "新代码已部署到 ${VN_DIR}"

# ---- 检查并自动修补 nginx.conf ----
# 新版本将 lua_package_path 移到了 in_http_block.conf（http 上下文）
# 旧 nginx.conf 可能只引用了 in_external.conf（main 上下文），缺少 http 块引用
info "=== Step 4b: 检查 nginx.conf 引用 ==="
NGINX_CONF="${VN_DIR}/openresty/nginx/conf/nginx.conf"
# 回退：如果 OpenResty 的 nginx.conf 不存在，检查安装目录顶层
if [ ! -f "${NGINX_CONF}" ]; then
    NGINX_CONF="${VN_DIR}/nginx.conf"
fi
HTTP_BLOCK_INCLUDE="include ${VN_DIR}/nginx_conf/in_http_block.conf;"

if [ -f "${NGINX_CONF}" ]; then
    if grep -q "in_http_block.conf" "${NGINX_CONF}" 2>/dev/null; then
        info "nginx.conf 已包含 in_http_block.conf"
    else
        warn "nginx.conf 缺少 in_http_block.conf，正在自动修补..."
        cp "${NGINX_CONF}" "${BACKUP_DIR}/nginx.conf.before_patch"
        # 在 http { 行后插入 include 行（缩进 4 空格）
        if grep -q "^http {" "${NGINX_CONF}" 2>/dev/null; then
            sed -i '/^http {/a\    '"${HTTP_BLOCK_INCLUDE}" "${NGINX_CONF}"
            info "已自动添加 in_http_block.conf 引用到 nginx.conf"
            info "备份原文件: ${BACKUP_DIR}/nginx.conf.before_patch"
        else
            error "无法自动修补：nginx.conf 中找不到 'http {' 行"
            error "请手动在 nginx.conf 的 http {} 块中添加："
            error "    ${HTTP_BLOCK_INCLUDE}"
            exit 1
        fi
    fi
else
    warn "未找到 ${NGINX_CONF}，跳过 nginx.conf 检查"
    warn "请确保 nginx.conf 的 http {} 块包含："
    warn "    ${HTTP_BLOCK_INCLUDE}"
fi

# ---- 恢复配置 ----
info "=== Step 5: 恢复用户配置 ==="

# 恢复全部 configs/ 用户数据（config.json、waf-rules.json、ip-reputation-flagged.json、backups/ 等）
if [ -d "${BACKUP_DIR}/configs" ]; then
    cp -r -f "${BACKUP_DIR}/configs/." "${VN_DIR}/configs/"
    info "恢复 configs/ 用户数据"
fi

if [ -f "${BACKUP_DIR}/geoip/GeoLite2-City.mmdb" ]; then
    mkdir -p "${VN_DIR}/geoip"
    cp "${BACKUP_DIR}/geoip/GeoLite2-City.mmdb" "${VN_DIR}/geoip/"
    info "恢复 GeoIP 数据库"
fi

# ---- 清理 ----
info "=== Step 6: 清理 ==="
rm -rf "${GIT_CLONE_DIR}" "${VN_DIR}/.verynginx_new"
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