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
VN_DIR="${VN_PREFIX}"
BACKUP_DIR="${VN_DIR}/configs/backups"
VN_ADMIN_PASSWORD=""

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
  if [ "$(id -u)" != "0" ]; then
    die "must run as root"
  fi
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

  if [ -z "$WEB_SERVER_BIN" ]; then
    die "no supported web server found (nginx/tengine/openresty)"
  fi
  if [ ! -f "$NGINX_CONF" ]; then
    die "nginx.conf not found at $NGINX_CONF"
  fi

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

  # Write version + git commit info for dashboard display
  if command -v git &>/dev/null && git -C "$src_dir" rev-parse --short HEAD &>/dev/null; then
    git -C "$src_dir" describe --tags --always > "${VN_DIR}/VERSION" 2>/dev/null \
      || echo "dev" > "${VN_DIR}/VERSION"
    git -C "$src_dir" rev-parse HEAD > "${VN_DIR}/COMMIT"
    info "Wrote version info ✓"
  else
    echo "dev" > "${VN_DIR}/VERSION"
    echo "unknown" > "${VN_DIR}/COMMIT"
  fi

  # config.json from template
  local config_file="${VN_DIR}/configs/config.json"
  if [ ! -f "$config_file" ]; then
    if [ -f "${VN_DIR}/configs/config.default.json" ]; then
      cp "${VN_DIR}/configs/config.default.json" "$config_file"
      info "Created config.json from default template"
    fi
  else
    info "config.json already exists, keeping it"
  fi

  # waf-rules.json from default template
  local rules_file="${VN_DIR}/configs/waf-rules.json"
  if [ ! -f "$rules_file" ]; then
    if [ -f "${VN_DIR}/configs/waf-rules.default.json" ]; then
      cp "${VN_DIR}/configs/waf-rules.default.json" "$rules_file"
      info "Created waf-rules.json from default template (20 rules)"
    fi
  else
    info "waf-rules.json already exists, keeping it"
  fi

  # Set admin password
  setup_admin_password "$config_file"

  # Make configs writable by nginx worker (Lua needs write access for
  # waf-rules.json persistence and writable-dir detection)
  local nginx_user
  nginx_user=$(grep -m1 '^\s*user\s' "$NGINX_CONF" 2>/dev/null | awk '{print $2}' | awk -F';' '{print $1}') || nginx_user=""
  if [ -n "$nginx_user" ] && id "$nginx_user" &>/dev/null; then
    chown -R "${nginx_user}:${nginx_user}" "${VN_DIR}/configs" 2>/dev/null || true
  fi
  chmod -R 755 "${VN_DIR}/configs"

  # Create GeoIP directory with proper permissions for DB downloads
  local geoip_dir="${VN_DIR}/geoip"
  mkdir -p "$geoip_dir"
  if [ -n "$nginx_user" ] && id "$nginx_user" &>/dev/null; then
    chown -R "${nginx_user}:${nginx_user}" "$geoip_dir"
  fi
  chmod 755 "$geoip_dir"
  info "Created GeoIP directory: ${geoip_dir}"

  # Ensure config.json has geoip.geodb_path set
  if [ -f "${VN_DIR}/configs/config.json" ]; then
    python3 -c "
import json, sys
cfg_path = '${VN_DIR}/configs/config.json'
with open(cfg_path) as f:
    cfg = json.load(f)
geoip = cfg.get('geoip', {})
if not geoip.get('geodb_path'):
    geoip['geodb_path'] = '${geoip_dir}/GeoLite2-City.mmdb'
    cfg['geoip'] = geoip
    with open(cfg_path, 'w') as f:
        json.dump(cfg, f, indent=4)
    print('  Updated geoip.geodb_path in config.json')
" 2>/dev/null || true
  fi

  info "Files installed to ${VN_DIR}"
}

# ----- admin password ------------------------------------------------------
setup_admin_password() {
  local config_file="$1"
  local default_user="verynginx"

  # Check if password already set
  if python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); exit(0 if c.get("admin",[{}])[0].get("password_hash","") else 1)' "$config_file" 2>/dev/null; then
    VN_ADMIN_PASSWORD="<already configured>"
    info "Admin password already configured, keeping it"
    return
  fi

  local password=""
  echo ""
  info "Setting admin password for the Dashboard"
  while :; do
    printf "Enter password for user '%s' (min 6 chars, leave empty for random): " "$default_user"
    read -rs password
    echo
    if [ -z "$password" ]; then
      password=$(dd if=/dev/urandom bs=12 count=1 2>/dev/null | base64 | tr -dc 'A-Za-z0-9')
      password="${password:0:12}"
      echo "  Generated password: ${password}"
      break
    elif [ ${#password} -ge 6 ]; then
      break
    else
      warn "Password too short (min 6 chars)"
    fi
  done

  export VN_PASSWORD="$password" VN_CONFIG="$config_file" VN_USER="$default_user"

  # Write Python script to temp file to avoid quoting hell
  local py_script
  py_script=$(mktemp /tmp/vn_hash.XXXXXX.py)
  cat > "$py_script" << 'PYEOF'
import os, hashlib, hmac, base64, json, secrets

password = os.environ['VN_PASSWORD'].encode('utf-8')
salt = os.urandom(16)
iterations = 12000

init_msg = salt + b'\x00\x00\x00\x01'
u = hmac.new(password, init_msg, 'sha256').digest()
result = bytearray(u)
for i in range(2, iterations + 1):
    u = hmac.new(password, u, 'sha256').digest()
    for j, b in enumerate(u):
        result[j] ^= b
result = bytes(result)
b64 = lambda d: base64.b64encode(d).decode('ascii')
hash_str = 'p1$%s$%s$%s' % (iterations, b64(salt), b64(result))

config = json.load(open(os.environ['VN_CONFIG']))
if 'admin' not in config or not config['admin']:
    config['admin'] = [{'user': os.environ['VN_USER'], 'enable': True}]
config['admin'][0]['password_hash'] = hash_str
config['admin'][0]['password'] = None
if not isinstance(config.get('security'), dict):
    config['security'] = {}
if not config['security'].get('session_secret'):
    config['security']['session_secret'] = secrets.token_hex(32)
json.dump(config, open(os.environ['VN_CONFIG'], 'w'), indent=4)
print('OK')
PYEOF

  local hash
  hash=$(python3 "$py_script" 2>&1) || die "Failed to generate password hash (python3 required)"
  rm -f "$py_script"

  if [ "$hash" = "OK" ]; then
    VN_ADMIN_PASSWORD="$password"
    info "Password set for user '${default_user}'"
    info "Save this password: ${password}"
  else
    warn "Password hash generation failed: $hash"
    warn "VeryNginx will auto-generate a password on first start (check error log)"
  fi
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

  # 1) upstream block inside http {} (upstream is only valid in http/stream context)
  if ! grep -q 'upstream vn_dynamic_upstream' "$NGINX_CONF" 2>/dev/null; then
    if grep -q '^http\s*{' "$NGINX_CONF"; then
      sed -i '/^http\s*{/a\
    # VeryNginx v2 - dynamic upstream for proxy_pass\
    upstream vn_dynamic_upstream {\
        server 0.0.0.1;\
        balancer_by_lua_block {\
            require("plugin.proxy_pass.balancer").run()\
        }\
        keepalive 128;\
    }
' "$NGINX_CONF"
      info "Added upstream vn_dynamic_upstream ✓"
    fi
  else
    info "upstream vn_dynamic_upstream already exists, skipping ✓"
  fi

  # 2) add VeryNginx paths to existing lua_package_path inside http block
  local vn_paths="${VN_DIR}/?.lua;${VN_DIR}/lua_script/?.lua;${VN_DIR}/lua_script/module/?.lua"
  local vn_cpath="${VN_DIR}/?.so"
  if grep -q 'lua_package_path' "$NGINX_CONF"; then
    # append VeryNginx paths if not already present
    if ! grep -q "${VN_DIR}" "$NGINX_CONF" 2>/dev/null; then
      sed -i "\|lua_package_path|s|;;|;${vn_paths};;|" "$NGINX_CONF"
      info "Merged VeryNginx paths into existing lua_package_path ✓"
    else
      info "VeryNginx paths already in lua_package_path, skipping ✓"
    fi
    # also ensure lua_package_cpath exists (ffi.load needs .so search path)
    if ! grep -q 'lua_package_cpath' "$NGINX_CONF"; then
      sed -i '/^http\s*{/a\    lua_package_cpath "'"${vn_cpath}"';;";' "$NGINX_CONF"
      info "Added lua_package_cpath ✓"
    fi
  else
    # no existing lua_package_path; add it
    sed -i '/^http\s*{/a\
    # VeryNginx v2 - Lua package paths\
    lua_package_path "'"${vn_paths}"';;";\
    lua_package_cpath "'"${vn_cpath}"';;";' "$NGINX_CONF"
    info "Added lua_package_path ✓"
  fi

  # 3) shared dicts + init blocks inside http {}
  if ! grep -q 'lua_shared_dict vn_config' "$NGINX_CONF" 2>/dev/null; then
    local insert_point
    insert_point=$(grep -n 'server_names_hash_bucket_size\|client_header_buffer_size\|sendfile\|keepalive_timeout' "$NGINX_CONF" | head -1 | cut -d: -f1)
    if [ -z "$insert_point" ]; then
      insert_point=$(grep -n '^http\s*{' "$NGINX_CONF" | head -1 | cut -d: -f1)
    fi

    sed -i "${insert_point}a\\
\\
    lua_code_cache on;\\
\\
    # VeryNginx v2 - shared dictionaries\\
    lua_shared_dict vn_config 2m;\\
    lua_shared_dict vn_locks 256k;\\
    lua_shared_dict vn_rate_limit 4m;\\
    lua_shared_dict vn_session 2m;\\
    lua_shared_dict ip_reputation 16m;\\
    lua_shared_dict statistics 20m;\\
    lua_shared_dict metrics 10m;\\
    lua_shared_dict healthcheck 10m;\\
    lua_shared_dict dns_cache 4m;\\
    lua_shared_dict frequency_limit 10m;\\
\\
    # VeryNginx v2 - main process initialization\\
    init_by_lua_block {\\
        require(\"core.init\").init()\\
    }\\
\\
    # VeryNginx v2 - worker-level timers\\
    init_worker_by_lua_block {\\
        require(\"core.init\").init_worker()\\
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
  # Check for NEW server-level format (unique comment marker in vn block)
  if grep -q 'VeryNginx v2 - server-level handlers' "$NGINX_CONF" 2>/dev/null; then
    info "Server-level VeryNginx handlers already present, skipping ✓"
  else
    replace_server_block
  fi


}

replace_server_block() {
  # Use python3 to parse nginx.conf and insert server-level Lua handlers
  # inside the first server {} block, so WAF covers ALL requests.
  local py_script
  py_script=$(mktemp /tmp/vn_replace.XXXXXX.py)
  cat > "$py_script" << 'PYEOF'
import re, sys

nginx_conf = sys.argv[1]
vn_dir = sys.argv[2]

with open(nginx_conf) as f:
    text = f.read()

# Check if new server-level format already exists
marker = '# VeryNginx v2 - server-level handlers (WAF for all requests)'
if marker in text:
    print("ALREADY_PRESENT")
    sys.exit(0)

# Find the first server { block
idx = text.find('server {')
if idx == -1:
    print("ERROR: no server block found")
    sys.exit(1)

# Find matching closing } for the server block
stack = []
for i in range(idx, len(text)):
    if text[i] == '{':
        stack.append(i)
    elif text[i] == '}':
        stack.pop()
        if not stack:
            server_end = i
            break
else:
    print("ERROR: unmatched braces in server block")
    sys.exit(1)

# Find position of '{' after 'server'
brace_pos = text.find('{', idx)
before = text[:brace_pos]
server_inner = text[brace_pos+1:server_end]
after = text[server_end:]

# --- Clean old VeryNginx Lua handlers from the server block ---
# (handles both location-level and server-level from previous installs)
lua_pattern = re.compile(
    r'^\s*(rewrite|access|log)_by_lua_file\s+' + re.escape(vn_dir) + r'/on_\w+\.lua\s*;\s*$',
    re.MULTILINE
)
server_inner = lua_pattern.sub('', server_inner)

# Remove empty location /verynginx/ { } blocks left after cleanup
server_inner = re.sub(
    r'^\s*location /verynginx/\s*\{\s*\}\s*\n?',
    '',
    server_inner,
    flags=re.MULTILINE
)

# Remove entire location /verynginx/static/ blocks (will be re-added)
# Match from "location /verynginx/static/ {" to matching "}"
def remove_loc(m):
    block = m.group(0)
    # Remove only if this is the old format (with alias but no Lua skip)
    # We'll always re-add, so just remove it.
    return ''
server_inner = re.sub(
    r'^\s*location /verynginx/static/ \{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}',
    '',
    server_inner,
    flags=re.MULTILINE
)

# Also remove location /verynginx/ { ... } blocks that contain old
# lua directives (may still have content_by_lua_file or other refs)
def remove_vn_loc(m):
    return ''
server_inner = re.sub(
    r'^\s*location /verynginx/ \{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}',
    '',
    server_inner,
    flags=re.MULTILINE
)

# --- Build new server-level directives ---
INDENT = '    '
vn_new = (
    '\n'
    + INDENT + '# VeryNginx v2 - server-level handlers (WAF for all requests)\n'
    + INDENT + 'rewrite_by_lua_file ' + vn_dir + '/on_rewrite.lua;\n'
    + INDENT + 'access_by_lua_file ' + vn_dir + '/on_access.lua;\n'
    + INDENT + 'log_by_lua_file ' + vn_dir + '/on_log.lua;\n'
    + '\n'
    + INDENT + '# VeryNginx dashboard static files (bypass Lua for performance)\n'
    + INDENT + 'location /verynginx/static/ {\n'
    + INDENT + '    alias ' + vn_dir + '/dashboard/;\n'
    + INDENT + '    access_by_lua_block { }\n'
    + INDENT + '    log_by_lua_block { }\n'
    + INDENT + '    expires epoch;\n'
    + INDENT + '    add_header X-Content-Type-Options "nosniff" always;\n'
    + INDENT + '    add_header X-Frame-Options "SAMEORIGIN" always;\n'
    + INDENT + '    add_header X-XSS-Protection "1; mode=block" always;\n'
    + INDENT + '    add_header Content-Security-Policy "default-src '
    + "'self' 'unsafe-inline' https://unpkg.com; "
    + "script-src 'self' 'unsafe-inline' https://unpkg.com; "
    + "style-src 'self' 'unsafe-inline'; "
    + "img-src 'self' data:; "
    + "connect-src 'self'; "
    + "frame-ancestors 'self'\" always;\n"
    + INDENT + '}\n'
    + '\n'
    + INDENT + '# VeryNginx v2 - API & dashboard (handled by router plugin)\n'
    + INDENT + 'location /verynginx/ {\n'
    + INDENT + '    # Managed by VeryNginx router plugin\n'
    + INDENT + '}\n'
)

result = text[:brace_pos+1] + server_inner + vn_new + after

with open(nginx_conf, 'w') as f:
    f.write(result)
print("OK")
PYEOF

  local out
  out=$(python3 "$py_script" "$NGINX_CONF" "$VN_DIR" 2>&1) || die "Failed to patch server block: $out"
  rm -f "$py_script"

  if [ "$out" = "OK" ]; then
    info "Server block patched with server-level VeryNginx handlers ✓"
    info "→ WAF now protects all requests in this server block"
    info "→ Dashboard: http://your-ip/verynginx/index.html"
  elif [ "$out" = "ALREADY_PRESENT" ]; then
    info "Server-level VeryNginx handlers already present, skipping ✓"
  else
    die "Server block patch failed: $out"
  fi
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
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      return 0
    else
      return 1
    fi
  fi
  pgrep -x nginx >/dev/null 2>&1
}

# ----- info output ---------------------------------------------------------
show_summary() {
  title "Installation complete"

  local host_ip
  host_ip=$(ip -4 route get 1 2>/dev/null | head -1 | awk '{print $7}') || host_ip="<your-server-ip>"

  echo ""
  echo "  ${BOLD}VeryNginx v2${NC} installed at: ${CYAN}${VN_DIR}${NC}"
  echo ""
  echo "  ${BOLD}Dashboard:${NC}"
  echo "    http://${host_ip}/verynginx/index.html"
  echo "    http://localhost/verynginx/index.html"
  echo ""
  echo "  ${BOLD}Admin account:${NC}"
  if [ -n "$VN_ADMIN_PASSWORD" ]; then
    echo "    Username: ${BOLD}verynginx${NC}"
    echo "    Password: ${VN_ADMIN_PASSWORD}"
  else
    echo "    Username: ${BOLD}verynginx${NC}"
    echo "    Password: ${YELLOW}<previously configured, check the first install output>${NC}"
  fi
  echo ""
  echo "  ${BOLD}After login:${NC}"
  echo "    Dashboard is available alongside your existing sites."
  echo "    Your current PHP-FPM handling is unchanged."
  echo ""
  echo "  ${BOLD}To enable WAF for a site:${NC}"
  echo "    Include this inside the site's server {} block:"
  echo "      include ${VN_DIR}/nginx_conf/in_server_block.conf;"
  echo ""
  echo "  ${BOLD}Useful commands:${NC}"
  echo "    nginx -t              # test configuration"
  echo "    systemctl reload nginx  # reload after manual edit"
  echo "    tail -f ${WEB_INSTALL_DIR}/logs/error.log  # monitor errors"
  echo ""
  echo "  ${BOLD}Kernel IP Blocking:${NC}"
  if [ -f "$FIREWALL_HELPER_BIN" ]; then
    echo "    Helper binary:  $FIREWALL_HELPER_BIN"
    echo "    Helper socket:  $FIREWALL_HELPER_SOCKET"
    echo "    Start helper:   systemctl start firewall-helper.socket"
  else
    echo "    Not installed (re-run install-lnmp.sh to add)"
  fi
  echo ""
}

# ----- main ----------------------------------------------------------------
show_help() {
  echo "VeryNginx v2 - LNMP Integration Install Script"
  echo ""
  echo "Usage: $0 [options]"
  echo "       $0 reset-password"
  echo ""
  echo "Options:"
  echo "  -h, --help         Show this help message"
  echo ""
  echo "Commands:"
  echo "  reset-password     Generate a new random admin password"
  echo ""
  echo "Environment:"
  echo "  VN_PREFIX     Install prefix (default: /opt/verynginx)"
  echo ""
  echo "This script installs VeryNginx v2 on an existing LNMP stack or"
  echo "any nginx/openresty with lua-nginx-module support."
  exit 0
}

# ----- reset admin password --------------------------------------------------
reset_admin_password() {
  # Generate a new random password, hash it, and write to config.json
  local config_file="${VN_DIR}/configs/config.json"
  if [ ! -f "$config_file" ]; then
    die "config.json not found at $config_file. Run install first."
  fi

  local password
  password=$(dd if=/dev/urandom bs=12 count=1 2>/dev/null | base64 | tr -dc 'A-Za-z0-9')
  password="${password:0:12}"

  export VN_PASSWORD="$password" VN_CONFIG="$config_file" VN_USER="verynginx"

  local py_script
  py_script=$(mktemp /tmp/vn_hash.XXXXXX.py)
  cat > "$py_script" << 'PYEOF'
import os, hashlib, hmac, base64, json, secrets

password = os.environ['VN_PASSWORD'].encode('utf-8')
salt = os.urandom(16)
iterations = 12000

init_msg = salt + b'\x00\x00\x00\x01'
u = hmac.new(password, init_msg, 'sha256').digest()
result = bytearray(u)
for i in range(2, iterations + 1):
    u = hmac.new(password, u, 'sha256').digest()
    for j, b in enumerate(u):
        result[j] ^= b
result = bytes(result)
b64 = lambda d: base64.b64encode(d).decode('ascii')
hash_str = 'p1$%s$%s$%s' % (iterations, b64(salt), b64(result))

config = json.load(open(os.environ['VN_CONFIG']))
if 'admin' not in config or not config['admin']:
    config['admin'] = [{'user': os.environ['VN_USER'], 'enable': True}]
config['admin'][0]['password_hash'] = hash_str
config['admin'][0]['password'] = None
if not isinstance(config.get('security'), dict):
    config['security'] = {}
if not config['security'].get('session_secret'):
    config['security']['session_secret'] = secrets.token_hex(32)
json.dump(config, open(os.environ['VN_CONFIG'], 'w'), indent=4)
print('OK')
PYEOF

  local hash_result
  hash_result=$(python3 "$py_script" 2>&1) || die "Failed to generate password hash (python3 required)"
  rm -f "$py_script"

  echo ""
  echo "  Admin password reset:"
  echo "    Username: verynginx"
  echo "    Password: ${password}"
  echo ""
  info "Password saved to ${VN_DIR}/configs/config.json"
  info "Restart nginx to apply: systemctl restart nginx"
  info "Then visit http://localhost/verynginx/index.html to login"
}

# ----- check GeoIP runtime dependencies -------------------------------------
# ---------------------------------------------------------------------------
# Check lua-resty-core / lua-resty-lrucache provides ngx.re.*, lrucache.
# Self-compiled nginx + lua-nginx-module departs these, but they must be
# on lua_package_path to work. Missing → runtime crash in matcher/rewrite.
# ---------------------------------------------------------------------------
check_lua_resty_deps() {
  title "Checking lua-resty-core / lua-resty-lrucache"

  # Common install locations for resty.core
  local resty_core_files=(
    "/usr/local/share/lua/5.1/resty/core.lua"
    "/usr/local/share/lua/5.1/resty/core.so"
    "/usr/share/lua/5.1/resty/core.lua"
    "/usr/share/lua/5.1/resty/core.so"
    "/usr/local/lib/lua/5.1/resty/core.so"
    "/usr/local/share/luajit-2.1.*/resty/core.lua"
  )
  local lrucache_files=(
    "/usr/local/share/lua/5.1/resty/lrucache.lua"
    "/usr/local/share/lua/5.1/resty/lrucache.so"
    "/usr/share/lua/5.1/resty/lrucache.lua"
    "/usr/share/lua/5.1/resty/lrucache.so"
  )

  local has_core=false
  for p in "${resty_core_files[@]}"; do
    for f in $p; do  # glob expansion
      if [ -f "$f" ]; then
        has_core=true
        info "lua-resty-core found: $f ✓"
        break 2
      fi
    done
  done

  local has_lrucache=false
  for p in "${lrucache_files[@]}"; do
    for f in $p; do
      if [ -f "$f" ]; then
        has_lrucache=true
        info "lua-resty-lrucache found: $f ✓"
        break 2
      fi
    done
  done

  if [ "$has_core" = "false" ] || [ "$has_lrucache" = "false" ]; then
    warn "lua-resty-core / lua-resty-lrucache not found — ngx.re.* and lrucache will fail"
    echo "  These are required for VeryNginx regex matching and rewrite rules."
    echo "  Install them (also bundled with OpenResty):"
    echo "    apt-get install -y libresty-core libresty-lrucache"
    echo "  Or from source:"
    echo "    git clone https://github.com/openresty/lua-resty-core.git"
    echo "    git clone https://github.com/openresty/lua-resty-lrucache.git"
    echo "    cd lua-resty-core && make install PREFIX=/usr/local"
    echo "    cd lua-resty-lrucache && make install PREFIX=/usr/local"
    if [ "$WEB_SERVER_TYPE" != "openresty" ]; then
      echo "  Hint: Switching to OpenResty bundles these libraries automatically."
    fi
  else
    info "lua-resty-core + lua-resty-lrucache: both found ✓"
  fi

  echo ""
}

check_geoip_deps() {
  title "Checking GeoIP dependencies"

  local all_ok=true

  # 1. Check LuaJIT / FFI support
  local has_luajit=false has_ffi=false
  local detection_method=""

  if [ "$WEB_SERVER_TYPE" = "openresty" ]; then
    has_luajit=true
    has_ffi=true
    detection_method="OpenResty built-in"
  fi

  # Check if nginx binary is linked against LuaJIT (ldd is the most reliable method)
  if [ "$has_luajit" = "false" ] && command -v ldd &>/dev/null; then
    if ldd "$WEB_SERVER_BIN" 2>/dev/null | grep -qi 'libluajit'; then
      has_luajit=true
      has_ffi=true
      detection_method="ldd (linked to libluajit)"
    fi
  fi

  # Check if luajit binary is available on the system
  if [ "$has_luajit" = "false" ] && command -v luajit &>/dev/null; then
    has_luajit=true
    has_ffi=true
    detection_method="luajit binary found"
  fi

  # Check nginx -V output as fallback
  if [ "$has_luajit" = "false" ]; then
    if "$WEB_SERVER_BIN" -V 2>&1 | grep -qi 'luajit'; then
      has_luajit=true
      has_ffi=true
      detection_method="nginx -V"
    fi
  fi

  if [ "$has_luajit" = "true" ]; then
    info "LuaJIT detected ($detection_method) → FFI available ✓"
  else
    warn "LuaJIT not detected — GeoIP requires FFI (LuaJIT)"
    echo "  If nginx is compiled with LuaJIT, install the luajit package:"
    echo "    apt-get install -y luajit libluajit-5.1-2 libluajit-5.1-dev"
    echo "  Or switch to OpenResty: https://openresty.org/en/installation.html"
    all_ok=false
  fi

  # 2. Check libmaxminddb C library
  local has_lib=false
  local lib_paths=(
    "/usr/lib/x86_64-linux-gnu/libmaxminddb.so"
    "/usr/lib/libmaxminddb.so"
    "/usr/local/lib/libmaxminddb.so"
    "/usr/lib64/libmaxminddb.so"
  )

  # Try ldconfig first
  if command -v ldconfig &>/dev/null; then
    if ldconfig -p 2>/dev/null | grep -q 'libmaxminddb\.so'; then
      has_lib=true
      info "libmaxminddb found via ldconfig ✓"
    fi
  fi

  # Fallback: check known paths
  if [ "$has_lib" = "false" ]; then
    for p in "${lib_paths[@]}"; do
      if [ -f "$p" ]; then
        has_lib=true
        info "libmaxminddb found at $p ✓"
        break
      fi
    done
  fi

  if [ "$has_lib" = "false" ]; then
    warn "libmaxminddb not found — GeoIP database lookups will fail"
    echo "  Install it: apt-get install -y libmaxminddb0 libmaxminddb-dev"
    echo "  or: yum install -y libmaxminddb libmaxminddb-devel"
    all_ok=false
  fi

  # 3. Check table.isarray / table.nkeys (bundled, should always be available)
  if [ -f "${PWD}/verynginx/table/isarray.lua" ] && [ -f "${PWD}/verynginx/table/nkeys.lua" ]; then
    info "table.isarray & table.nkeys modules bundled ✓"
  else
    warn "table.isarray / table.nkeys not found in source tree"
  fi

  # Summary
  echo ""
  if [ "$all_ok" = "true" ]; then
    info "GeoIP dependencies: all satisfied ✓"
  else
    warn "GeoIP dependencies: some missing (see above)"
    info "VeryNginx will still work, but GeoIP features will be unavailable."
    info "GeoIP can be enabled later after installing the missing dependencies."
  fi
}

# ----- Firewall Helper (Go) ------------------------------------------------
# Probes nftables capabilities and deploys the privileged Helper process.
# The Helper is a static Go binary that bridges VeryNginx Lua workers to
# kernel nftables via a Unix Domain Socket.
FIREWALL_HELPER_BIN="/usr/local/bin/firewall-helper"
FIREWALL_HELPER_SOCKET="/run/verynginx/firewall-helper.sock"
FIREWALL_HELPER_DIR="/run/verynginx"

probe_nftables_capabilities() {
  title "Probing nftables capabilities"

  local nft_cmd=""
  if command -v nft >/dev/null 2>&1; then
    nft_cmd="$(command -v nft)"
  fi

  if [ -z "$nft_cmd" ]; then
    warn "nft command not found — kernel IP blocking will be disabled"
    echo "  Install nftables user-space tools:"
    echo "    apt-get install -y nftables"
    echo "    yum install -y nftables"
    return 1
  fi

  info "nft command found: $nft_cmd ✓"

  # Check kernel nftables support
  if ! "$nft_cmd" list tables >/dev/null 2>&1; then
    warn "nft list tables failed — kernel may lack nftables support"
    echo "  Kernel IP blocking requires Linux 3.13+ with CONFIG_NF_TABLES"
    return 1
  fi
  info "kernel nftables operational ✓"

  # Probe capabilities by creating a temporary table
  local probe_table="vn_probe_$$"
  local probe_ok=true

  # Test 1: inet family (dual ipv4/ipv6)
  if "$nft_cmd" add table inet "$probe_table" 2>/dev/null; then
    if "$nft_cmd" add set inet "$probe_table" test_set '{ type ipv4_addr; flags interval; }' 2>/dev/null; then
      info "inet family + interval set: supported ✓"
      "$nft_cmd" delete set inet "$probe_table" test_set 2>/dev/null
    else
      warn "interval set: not supported"
      probe_ok=false
    fi
    # Test timeout element
    if "$nft_cmd" add set inet "$probe_table" test_timeout '{ type ipv4_addr; flags timeout; }' 2>/dev/null; then
      if "$nft_cmd" add element inet "$probe_table" test_timeout '{ 192.0.2.1 timeout 60s }' 2>/dev/null; then
        info "timeout element: supported ✓"
        "$nft_cmd" delete element inet "$probe_table" test_timeout '{ 192.0.2.1 }' 2>/dev/null
      else
        warn "timeout element: not supported"
        probe_ok=false
      fi
      "$nft_cmd" delete set inet "$probe_table" test_timeout 2>/dev/null
    fi
    "$nft_cmd" delete table inet "$probe_table" 2>/dev/null
  else
    warn "inet family: not supported"
    probe_ok=false
    # Fallback: try ip family only
    if "$nft_cmd" add table ip "$probe_table" 2>/dev/null; then
      info "ip family (ipv4 only): supported ✓"
      "$nft_cmd" delete table ip "$probe_table" 2>/dev/null
    fi
  fi

  if [ "$probe_ok" = "true" ]; then
    info "nftables capabilities: all satisfied ✓"
  else
    warn "nftables capabilities: partial — kernel IP blocking may be limited"
  fi
  return 0
}

install_firewall_helper() {
  title "Installing Firewall Helper (Go)"

  # Check if Go is available
  local go_cmd=""
  if command -v go >/dev/null 2>&1; then
    go_cmd="$(command -v go)"
  fi

  if [ -z "$go_cmd" ]; then
    warn "Go compiler not found — skipping Helper build"
    echo "  To build the Helper later:"
    echo "    1. Install Go 1.21+: https://go.dev/dl/"
    echo "    2. cd helper && go build -o firewall-helper ."
    echo "    3. cp firewall-helper /usr/local/bin/"
    return 0
  fi

  local go_version
  go_version=$("$go_cmd" version 2>/dev/null | awk '{print $3}' | sed 's/go//')
  info "Go version: $go_version"

  # Build the helper
  local helper_src="${PWD}/helper"
  if [ ! -d "$helper_src" ]; then
    warn "helper/ source directory not found — skipping build"
    return 0
  fi

  info "Building firewall-helper..."
  if (cd "$helper_src" && "$go_cmd" build -o firewall-helper . 2>&1); then
    info "Build successful ✓"
  else
    warn "Build failed — kernel IP blocking will be unavailable"
    echo "  Build manually: cd helper && go build -o firewall-helper ."
    return 0
  fi

  # Install binary
  cp "${helper_src}/firewall-helper" "$FIREWALL_HELPER_BIN"
  chmod 755 "$FIREWALL_HELPER_BIN"
  info "Installed: $FIREWALL_HELPER_BIN ✓"

  # Create socket directory
  mkdir -p "$FIREWALL_HELPER_DIR"
  chmod 755 "$FIREWALL_HELPER_DIR"
  info "Socket directory: $FIREWALL_HELPER_DIR ✓"

  # Install systemd units if systemd is present
  if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
    info "Installing systemd socket activation units..."

    # Write socket unit
    cat > /etc/systemd/system/firewall-helper.socket <<SOCKUNIT
[Unit]
Description=VeryNginx Firewall Helper Socket
Before=nginx.service

[Socket]
ListenStream=${FIREWALL_HELPER_SOCKET}
SocketMode=0666
DirectoryMode=0755

[Install]
WantedBy=sockets.target
SOCKUNIT

    # Write service unit
    cat > /etc/systemd/system/firewall-helper.service <<SVCUNIT
[Unit]
Description=VeryNginx Firewall Helper (nftables kernel IP blocking)
After=network.target
Requires=firewall-helper.socket

[Service]
Type=simple
ExecStart=${FIREWALL_HELPER_BIN}
Restart=on-failure
RestartSec=1
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=${FIREWALL_HELPER_DIR}
RuntimeDirectory=verynginx
ExecStartPre=/bin/mkdir -p ${FIREWALL_HELPER_DIR}

[Install]
WantedBy=multi-user.target
SVCUNIT

    systemctl daemon-reload
    systemctl enable firewall-helper.socket
    info "systemd units installed ✓"
    info "Start with: systemctl start firewall-helper.socket"
  else
    warn "systemd not detected — Helper must be started manually"
    echo "  Run: $FIREWALL_HELPER_BIN &"
    echo "  Or create a systemd unit from helper/firewall-helper.{socket,service}"
  fi

  # Set socket permissions so nginx worker can connect
  # nginx typically runs as www-data or nginx
  if id www-data >/dev/null 2>&1; then
    chown www-data:www-data "$FIREWALL_HELPER_DIR" 2>/dev/null || true
  elif id nginx >/dev/null 2>&1; then
    chown nginx:nginx "$FIREWALL_HELPER_DIR" 2>/dev/null || true
  fi
  chmod 755 "$FIREWALL_HELPER_DIR"

  info "Firewall Helper installation complete"
  echo "  Binary:  $FIREWALL_HELPER_BIN"
  echo "  Socket:  $FIREWALL_HELPER_SOCKET"
  echo "  Mode:    observe (default — change to enforce in Config → Kernel Blocking)"
}
main() {
  for arg in "$@"; do
    case "$arg" in
      -h|--help) show_help ;;
      reset-password|reset-admin-password)
        require_root
        VN_PREFIX="${VN_PREFIX:-/opt/verynginx}"
        VN_DIR="${VN_PREFIX}"
        reset_admin_password
        exit 0
        ;;
    esac
  done

  require_root
  detect_web_server
  check_lua_resty_deps
  check_geoip_deps
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

  # Firewall Helper (kernel IP blocking)
  echo ""
  confirm "Install Firewall Helper for kernel IP blocking?" DO_HELPER "y"
  if [ "$DO_HELPER" = "y" ]; then
    probe_nftables_capabilities
    install_firewall_helper
  else
    info "Skipping Firewall Helper installation"
    info "You can install it later by re-running install-lnmp.sh"
  fi

  show_summary
}

main "$@"

