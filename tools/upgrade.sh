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
# 升级必须固定到具体 commit：浮动分支意味着任何能改写 v2 指针的人
# （包括被入侵的维护者账号）都能让所有跑升级脚本的机器直接部署恶意代码。
# ---- 供应链信任模型（务必理解后再改）----
# 升级的信任锚是【安装时部署的本脚本副本】：其 VN_PINNED_COMMIT 在安装时
# 被烘焙为当次安装对应的 commit，仓库分支被改写也影响不到已部署的锚
# （git checkout <sha> 得到的内容由 git 对象模型保证，不可篡改）。
# 注意：绝不要用 curl|bash 从分支上取本脚本再运行——那样 pin 就落在改写
# 分支的人手里，等于没有 pin（这正是旧版 pin 被判为假修复的原因）。
# 前进方式：查 release 说明确认目标 commit，显式 VN_UPGRADE_COMMIT=<sha>
# 覆盖（脚本会大声警告）；升级部署的新代码会携带新的锚供下次使用。
VN_PINNED_COMMIT="b2c0f5dd9d7adfa1632841a54d6847be7c86db2e"
VN_UPGRADE_COMMIT="${VN_UPGRADE_COMMIT:-${VN_PINNED_COMMIT}}"
if [ -n "${VN_UPGRADE_COMMIT:-}" ] && [ "${VN_UPGRADE_COMMIT}" != "${VN_PINNED_COMMIT}" ]; then
    warn "=========================================================="
    warn "VN_UPGRADE_COMMIT 覆盖生效: ${VN_UPGRADE_COMMIT}"
    warn "内置 pin: ${VN_PINNED_COMMIT}"
    warn "覆盖将绕过 supply-chain pin —— 请确认该 commit 来自可信渠道"
    warn "=========================================================="
fi
git clone \
    "https://github.com/nengfeng/VeryNginx.git" \
    "${GIT_CLONE_DIR}" 2>&1 || {
    error "克隆失败，请检查网络或 GitHub 访问"
    rm -rf "${GIT_CLONE_DIR}"
    exit 1
}
git -C "${GIT_CLONE_DIR}" checkout --quiet "${VN_UPGRADE_COMMIT}" 2>&1 || {
    error "checkout ${VN_UPGRADE_COMMIT} 失败：commit 不存在或仓库异常"
    rm -rf "${GIT_CLONE_DIR}"
    exit 1
}
info "代码拉取完成 (commit: $(cd ${GIT_CLONE_DIR} && git rev-parse --short HEAD))"
# Staleness visibility: an installed anchor is expected to lag the branch;
# make the gap explicit so "升级成功" never silently means "冻结在旧代码".
PIN_BEHIND=$(git -C "${GIT_CLONE_DIR}" rev-list --count "${VN_UPGRADE_COMMIT}..origin/v2" 2>/dev/null || echo "?")
if [ -n "${PIN_BEHIND}" ] && [ "${PIN_BEHIND}" != "0" ]; then
    info "注意: 所用 commit 落后 v2 分支 ${PIN_BEHIND} 个提交；如需最新请查 release 说明后显式指定 VN_UPGRADE_COMMIT"
fi

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

# 自更新升级脚本：checkout 过的（pin=本次 commit）脚本替换本机旧锚，
# 下次升级的默认 pin 即本次版本——否则锚永远停在安装时版本，
# 每次升级都得显式 VN_UPGRADE_COMMIT。脚本本体来自已验证的 checkout，信任链成立。
if [ -f "${GIT_CLONE_DIR}/tools/upgrade.sh" ]; then
    mkdir -p "${VN_DIR}/tools"
    if cp "${GIT_CLONE_DIR}/tools/upgrade.sh" "${VN_DIR}/tools/upgrade.sh"         && chmod 750 "${VN_DIR}/tools/upgrade.sh"; then
        info "本机升级脚本已随本次版本更新（下次升级默认锚 = 本次 commit）"
    else
        warn "升级脚本自更新失败——下次升级仍需显式 VN_UPGRADE_COMMIT"
    fi
fi

# ---- Step 4c: Firewall Helper (Go) ----
# helper 是独立编译的宿主二进制（/usr/local/bin/firewall-helper），上面的
# verynginx/ 树覆盖不会带上它——reconcile 守卫、conn deadline、flush 范围
# 等 §11 修复都在 helper 里。已装机器必须在这里重建换装，否则升级后 Lua
# 与 helper 版本脱节（ observe/enforce 行为与文档不符）。
info "=== Step 4c: Firewall Helper ==="
FIREWALL_HELPER_BIN="/usr/local/bin/firewall-helper"
HELPER_INSTALLED=false
[ -x "$FIREWALL_HELPER_BIN" ] && HELPER_INSTALLED=true

if [ ! -d "${GIT_CLONE_DIR}/helper" ]; then
    info "checkout 中无 helper/ 源码，跳过 helper 重建"
elif [ "$HELPER_INSTALLED" != true ]; then
    info "本机未安装 helper（/usr/local/bin/firewall-helper 不存在），跳过重建"
else
    GO_CMD=""
    if command -v go >/dev/null 2>&1; then
        GO_CMD="$(command -v go)"
    elif [ -x /usr/local/go/bin/go ]; then
        GO_CMD="/usr/local/go/bin/go"
    fi

    if [ -z "$GO_CMD" ]; then
        warn "Go 未安装——helper 二进制未更新，本轮 helper 修复（reconcile 守卫/conn deadline/flush 范围）未生效"
        warn "手动重建: 安装 Go 1.21+ 后 cd ${GIT_CLONE_DIR}/helper && go build -o ${FIREWALL_HELPER_BIN} . && systemctl try-restart firewall-helper.service"
    else
        info "重建 firewall-helper (go: $GO_CMD)..."
        if (cd "${GIT_CLONE_DIR}/helper" && "$GO_CMD" build -o "${GIT_CLONE_DIR}/helper/firewall-helper" . 2>&1); then
            # 无变化则不重启：二进制一致时保持现状
            if cmp -s "${GIT_CLONE_DIR}/helper/firewall-helper" "$FIREWALL_HELPER_BIN"; then
                info "helper 二进制无变化，跳过换装"
            else
                # ETXTBSY：运行中的旧二进制不能被 cp 覆盖——先停单元，
                # 再 tmp+rename 原子换装（与 install-lnmp.sh 同约定）
                _HELPER_WAS_ACTIVE=0
                if command -v systemctl >/dev/null 2>&1; then
                    if systemctl is-active --quiet firewall-helper.service 2>/dev/null; then
                        _HELPER_WAS_ACTIVE=1
                        systemctl stop firewall-helper.socket 2>/dev/null || true
                        systemctl stop firewall-helper.service 2>/dev/null || true
                    fi
                fi
                _HELPER_TMP="${FIREWALL_HELPER_BIN}.upgrade.$$"
                if cp "${GIT_CLONE_DIR}/helper/firewall-helper" "$_HELPER_TMP" \
                    && chmod 755 "$_HELPER_TMP" \
                    && mv -f "$_HELPER_TMP" "$FIREWALL_HELPER_BIN"; then
                    info "helper 已换装: $FIREWALL_HELPER_BIN ✓"
                else
                    warn "helper 换装失败（旧二进制保持原样）；手动: cd ${GIT_CLONE_DIR}/helper && go build -o ${FIREWALL_HELPER_BIN} ."
                fi
                mkdir -p /run/verynginx && chmod 755 /run/verynginx 2>/dev/null || true
                # systemd 单元如有变化一并部署
                for _unit in firewall-helper.socket firewall-helper.service; do
                    if [ -f "${GIT_CLONE_DIR}/helper/${_unit}" ]; then
                        if ! cmp -s "${GIT_CLONE_DIR}/helper/${_unit}" "/etc/systemd/system/${_unit}" 2>/dev/null; then
                            cp "${GIT_CLONE_DIR}/helper/${_unit}" "/etc/systemd/system/${_unit}" \
                                && _UNITS_CHANGED=1 \
                                && info "已更新 systemd 单元: ${_unit}" \
                                || warn "systemd 单元 ${_unit} 更新失败"
                        fi
                    fi
                done
                if command -v systemctl >/dev/null 2>&1; then
                    [ "${_UNITS_CHANGED:-0}" = 1 ] && systemctl daemon-reload 2>/dev/null || true
                    if [ "${_HELPER_WAS_ACTIVE}" = 1 ]; then
                        systemctl start firewall-helper.socket 2>/dev/null \
                            && info "firewall-helper.socket 已重新启动 ✓" \
                            || warn "firewall-helper.socket 启动失败，请手动检查: systemctl status firewall-helper.socket"
                    fi
                fi
            fi
        else
            warn "helper 构建失败（旧二进制保持原样）；手动: cd ${GIT_CLONE_DIR}/helper && go build -o ${FIREWALL_HELPER_BIN} ."
        fi
    fi
fi

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