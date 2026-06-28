#!/bin/bash
# VeryNginx v2 - LNMP Integration Install Script
# SPDX-License-Identifier: Apache-2.0
#
# Installs VeryNginx v2 on top of an existing LNMP stack
# (https://github.com/nengfeng/lnmp) or any nginx/openresty
# installation with lua-nginx-module.
#
# Usage:
#   ./install-lnmp.sh                    # interactive
#   ./install-lnmp.sh --help|-h          # show help
#
# Environment variables:
#   VN_PREFIX=/opt/verynginx    install prefix (default: /opt/verynginx)

set -euo pipefail

# ----- constants -----------------------------------------------------------
VN_PREFIX="${VN_PREFIX:-/opt/verynginx}"
VN_DIR="${VN_PREFIX}/verynginx"
BACKUP_DIR="${VN_DIR}/configs/backups"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'
NC='\033[0m'; BOLD='\033[1m'

# ----- helpers -------------------------------------------------------------
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
title() { echo -e "\n${BOLD}━━━ $* ━━━${NC}\n"; }

die() { error "$*"; exit 1; }

confirm() {
  local prompt="$1" var="$2" default="${3:-n}" val
  while :; do
    printf "%s [y/n] (default: %s): " "$prompt" "$default"
    read -r val; val="${val:-$default}"
    case "$val" in y|Y) eval "$var=y"; break;; n|N) eval "$var=n"; break;; esac
  done
}

require_root() {
  [ "$(id -u)" != "0" ] && die "must run as root"
}

# ----- detect web server ---------------------------------------------------
detect_web_server() {
  title "Detecting web server"

  local candidates=(
    "/usr/local/openresty/nginx/sbin/nginx:openresty"
    "/usr/local/nginx/sbin/nginx:nginx"
    "/usr/local/tengine/sbin/nginx:tengine"
    "/opt/verynginx/openresty/nginx/sbin/nginx:openresty"
    "/usr/sbin/nginx:system"
  )

  WEB_SERVER_BIN=""; WEB_SERVER_TYPE=""; WEB_INSTALL_DIR=""; NGINX_CONF=""

  for pair in "${candidates[@]}"; do
    local bin="${pair%%:*}" type="${pair##*:}"
    if [ -x "$bin" ]; then
      WEB_SERVER_BIN="$bin"; WEB_SERVER_TYPE="$type"
      case "$type" in
        openresty) WEB_INSTALL_DIR="${bin%/nginx/sbin/nginx}"; NGINX_CONF="${WEB_INSTALL_DIR}/nginx/conf/nginx.conf" ;;
        nginx|tengine) WEB_INSTALL_DIR="${bin%/sbin/nginx}"; NGINX_CONF="${WEB_INSTALL_DIR}/conf/nginx.conf" ;;
        system) WEB_INSTALL_DIR="$(dirname "$(dirname "$bin")")"; NGINX_CONF="/etc/nginx/nginx.conf"; WEB_SERVER_TYPE="nginx" ;;
      esac
      break
    fi
  done

  [ -z "$WEB_SERVER_BIN" ] && die "no supported web server found (nginx/tengine/openresty)"
  [ ! -f "$NGINX_CONF" ]  && die "nginx.conf not found at $NGINX_CONF"

  info "Web server: ${BOLD}$WEB_SERVER_TYPE${NC} → ${WEB_SERVER_BIN}"
  info "Config:     ${NGINX_CONF}"

  # verify lua support
  if ! "$WEB_SERVER_BIN" -V 2>&1 | grep -q 'lua-nginx-module'; then
    if [ "$WEB_SERVER_TYPE" = "openresty" ]; then
      info "OpenResty has built-in Lua support ✓"
    else
      die "lua-nginx-module not detected in nginx -V. Install via LNMP first."
    fi
  else
    info "lua-nginx-module detected ✓"
  fi

  # detect LNMP (informational only)
  if grep -q 'include vhost/\*\.conf;' "${NGINX_CONF}" 2>/dev/null; then
    info "LNMP stack detected ✓"
  fi
}

# ----- copy files ----------------------------------------------------------
install_files() {
  title "Installing VeryNginx files"

  local src_dir
  src_dir="$(cd "$(dirname "$0")" && pwd)"

  if [ ! -d "${src_dir}/verynginx" ]; then
    die "Cannot find verynginx/ directory. Run this script from the VeryNginx repo root."
  fi

  mkdir -p "${VN_DIR}" "${BACKUP_DIR}"
  cp -r "${src_dir}/verynginx/"* "${VN_DIR}/"

  # config.json from template
  if [ ! -f "${VN_DIR}/configs/config.json" ]; then
    if [ -f "${VN_DIR}/configs/config.default.json" ]; then
      cp "${VN_DIR}/configs/config.default.json" "${VN_DIR}/configs/config.json"
      info "Created config.json from default template"
      info "${YELLOW}→ An admin password will be auto-generated on first start${NC}"
    fi
  else
    info "config.json already exists, keeping it"
  fi

  chmod -R 755 "${VN_DIR}/configs"
  info "Files installed to ${VN_DIR}"
}

# ----- backup nginx.conf ---------------------------------------------------
backup_nginx_conf() {
  local bak="${NGINX_CONF}.bak.$(date +%Y%m%d-%H%M%S)"
  cp "$NGINX_CONF" "$bak"
  info "Backup saved: ${bak}"
}

# ----- inject directives into nginx.conf -----------------------------------
patch_nginx_conf() {
  title "Patching nginx.conf"

  backup_nginx_conf

  # 1) upstream block before http {}
  if ! grep -q 'upstream vn_dynamic_upstream' "$NGINX_CONF" 2>/dev/null; then
    if grep -q '^http\s*{' "$NGINX_CONF"; then
      sed -i '/^http\s*{/i\
# VeryNginx v2 - dynamic upstream for proxy_pass\
upstream vn_dynamic_upstream {\
    server 0.0.0.1;\
    balancer_by_lua_block {\
        require("plugin.proxy_pass.balancer").run()\
    }\
    keepalive 128;\
}\
' "$NGINX_CONF"
      info "Added upstream vn_dynamic_upstream ✓"
    fi
  else
    info "upstream vn_dynamic_upstream already exists, skipping ✓"
  fi

  # 2) add VeryNginx paths to existing lua_package_path inside http block
  local vn_paths="${VN_DIR}/?.lua;${VN_DIR}/lua_script/?.lua;${VN_DIR}/lua_script/module/?.lua"
  if grep -q 'lua_package_path' "$NGINX_CONF"; then
    # append VeryNginx paths if not already present
    if ! grep -q "${VN_DIR}" "$NGINX_CONF" 2>/dev/null; then
      sed -i "/lua_package_path/s/;;/;${vn_paths};;/" "$NGINX_CONF"
      info "Merged VeryNginx paths into existing lua_package_path ✓"
    else
      info "VeryNginx paths already in lua_package_path, skipping ✓"
    fi
  else
    # no existing lua_package_path; add it
    sed -i '/^http\s*{/a\
    # VeryNginx v2 - Lua package paths\
    lua_package_path "'"${vn_paths}"';;";\
    lua_package_cpath "'"${VN_DIR}"'?.so;;";' "$NGINX_CONF"
    info "Added lua_package_path ✓"
  fi

  # 3) shared dicts + init blocks inside http {}
  if ! grep -q 'lua_shared_dict vn_config' "$NGINX_CONF" 2>/dev/null; then
    local insert_point
    insert_point=$(grep -n 'server_names_hash_bucket_size\|client_header_buffer_size\|sendfile\|keepalive_timeout' "$NGINX_CONF" | head -1 | cut -d: -f1)
    [ -z "$insert_point" ] && insert_point=$(grep -n '^http\s*{' "$NGINX_CONF" | head -1 | cut -d: -f1)

    sed -i "${insert_point}a\\
\\
    # VeryNginx v2 - shared dictionaries\\
    lua_shared_dict vn_config 2m;\\
    lua_shared_dict vn_locks 1m;\\
    lua_shared_dict statistics 20m;\\
    lua_shared_dict metrics 10m;\\
    lua_shared_dict healthcheck 10m;\\
    lua_shared_dict dns_cache 4m;\\
    lua_shared_dict frequency_limit 10m;\\
\\
    # VeryNginx v2 - main process initialization\\
    init_by_lua_block {\\
        require("core.init").init()\\
    }\\
\\
    # VeryNginx v2 - worker-level timers\\
    init_worker_by_lua_block {\\
        require("core.init").init_worker()\\
    }\\
\\
    # WebSocket connection upgrade\\
    map \$http_upgrade \$connection_upgrade {\\
        default upgrade;\\
        '' close;\\
    }" "$NGINX_CONF"
    info "Added shared dicts and init blocks ✓"
  else
    info "Shared dicts already present, skipping ✓"
  fi

  # 4) server block directives
  if ! grep -q 'rewrite_by_lua_file.*on_rewrite' "$NGINX_CONF" 2>/dev/null; then
    replace_server_block
  else
    info "Server block Lua directives already present, skipping ✓"
  fi


}

replace_server_block() {
  # Find the first server {} block inside http {}
  local http_line server_start server_end

  http_line=$(grep -n '^http\s*{' "$NGINX_CONF" | head -1 | cut -d: -f1)
  [ -z "$http_line" ] && die "Cannot find http {} block in nginx.conf"

  # Use awk to find the first server block after http { and its matching }
  eval "$(awk '
    NR > '"$http_line"' && /^[[:space:]]*server[[:space:]]*\{/ {
      start = NR;
      bc = 1;
      while (bc > 0) {
        if (getline <= 0) break;
        o = gsub(/\{/, "&"); c = gsub(/\}/, "&"); bc += o - c;
      }
      print "server_start=" start;
      print "server_end=" NR;
      exit;
    }
  ' "$NGINX_CONF")"

  [ -z "$server_start" ] && die "Cannot find server {} block in nginx.conf"

  # Build the VeryNginx location blocks
  local vn_block
  read -r -d '' vn_block << VNB
        # VeryNginx v2 - API & dashboard
        location /verynginx/ {
            rewrite_by_lua_file ${VN_DIR}/on_rewrite.lua;
            access_by_lua_file ${VN_DIR}/on_access.lua;
            log_by_lua_file ${VN_DIR}/on_log.lua;
        }
        location /verynginx/static/ {
            alias ${VN_DIR}/dashboard/;
            expires epoch;
            add_header X-Content-Type-Options "nosniff" always;
            add_header X-Frame-Options "SAMEORIGIN" always;
            add_header X-XSS-Protection "1; mode=block" always;
        }
VNB

  # Insert vn_block before the closing } of the server block
  local tmpfile
  tmpfile=$(mktemp)
  {
    sed -n "1,$((server_end - 1))p" "$NGINX_CONF"
    echo "$vn_block"
    sed -n "${server_end},\$p" "$NGINX_CONF"
  } > "$tmpfile"
  mv "$tmpfile" "$NGINX_CONF"

  info "Server block patched with VeryNginx locations ✓"
  info "→ Dashboard: http://your-ip/verynginx/index.html"
  warn "Existing PHP-FPM handling is preserved"
  warn "→ For full WAF protection, add VeryNginx location / block manually (see docs)"
}

# ----- nginx test & reload -------------------------------------------------
reload_nginx() {
  title "Testing nginx configuration"

  if "$WEB_SERVER_BIN" -t 2>&1; then
    info "nginx configuration test passed ✓"
    if svc_is_active nginx 2>/dev/null; then
      if command -v systemctl >/dev/null 2>&1; then
        systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true
      else
        "$WEB_SERVER_BIN" -s reload 2>/dev/null || true
      fi
      info "nginx reloaded ✓"
    else
      warn "nginx is not running. Start it with: systemctl start nginx"
    fi
  else
    error "nginx configuration test FAILED"
    error "Check ${NGINX_CONF} for errors"
    error "Backup saved alongside original. Manual fix required."
    exit 1
  fi
}

svc_is_active() {
  local svc="$1"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet "$svc" 2>/dev/null && return 0 || return 1
  fi
  pgrep -x nginx >/dev/null 2>&1
}

# ----- info output ---------------------------------------------------------
show_summary() {
  title "Installation complete"

  local host_ip
  host_ip=$(ip -4 route get 1 2>/dev/null | head -1 | awk '{print $7}') || host_ip="your-server-ip"

  echo ""
  echo "  ${BOLD}VeryNginx v2${NC} installed at: ${CYAN}${VN_DIR}${NC}"
  echo ""
  echo "  ${BOLD}Dashboard:${NC}"
  echo "    http://${host_ip}/verynginx/index.html"
  echo ""
  echo "  ${BOLD}Admin account:${NC}"
  echo "    Username: verynginx"
  echo "    Password: ${YELLOW}auto-generated on first start${NC}"
  echo "    → Check nginx error log:"
  echo "      grep 'generated admin password' ${WEB_INSTALL_DIR}/logs/error.log 2>/dev/null ||"
  echo "      journalctl -u nginx | grep 'generated admin password' 2>/dev/null ||"
  echo '      grep "generated admin password" /var/log/nginx/error.log'
  echo ""
  echo "  ${BOLD}After login:${NC}"
  echo "    Dashboard is available alongside your existing sites."
  echo "    Your current PHP-FPM handling is unchanged."
  echo ""
  echo "  ${BOLD}To enable WAF for a site:${NC}"
  echo "    Add this inside the site's server {} block:"
  echo '      rewrite_by_lua_file  '"${VN_DIR}"'/on_rewrite.lua;'
  echo '      access_by_lua_file   '"${VN_DIR}"'/on_access.lua;'
  echo '      log_by_lua_file      '"${VN_DIR}"'/on_log.lua;'
  echo "    Then configure an upstream in Dashboard → Settings → Upstreams"
  echo ""
  echo "  ${BOLD}Useful commands:${NC}"
  echo "    nginx -t              # test configuration"
  echo "    systemctl reload nginx  # reload after manual edit"
  echo "    tail -f ${WEB_INSTALL_DIR}/logs/error.log  # monitor errors"
  echo ""
}

# ----- main ----------------------------------------------------------------
show_help() {
  echo "VeryNginx v2 - LNMP Integration Install Script"
  echo ""
  echo "Usage: $0 [options]"
  echo ""
  echo "Options:"
  echo "  -h, --help    Show this help message"
  echo ""
  echo "Environment:"
  echo "  VN_PREFIX     Install prefix (default: /opt/verynginx)"
  echo ""
  echo "This script installs VeryNginx v2 on an existing LNMP stack or"
  echo "any nginx/openresty with lua-nginx-module support."
  exit 0
}

main() {
  for arg in "$@"; do
    case "$arg" in -h|--help) show_help ;; esac
  done

  require_root
  detect_web_server
  install_files

  echo ""
  confirm "Patch nginx.conf to enable VeryNginx?" DO_PATCH "y"
  if [ "$DO_PATCH" = "y" ]; then
    patch_nginx_conf
    reload_nginx
  else
    info "Skipping nginx.conf patching"
    info "Manually add these includes to your nginx.conf:"
    echo "  include ${VN_DIR}/nginx_conf/in_external.conf;       # outside http {}"
    echo "  include ${VN_DIR}/nginx_conf/in_http_block.conf;     # inside http {}"
    echo "  include ${VN_DIR}/nginx_conf/in_server_block.conf;   # inside server {}"
  fi

  show_summary
}

main "$@"
