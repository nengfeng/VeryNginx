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
# Build fingerprint so field logs self-identify the exact code being run
# Canonical script location — ALL source-tree references must use this, never
# ${PWD}: running the script by absolute path from another directory (e.g.
# `cd /root && /opt/src/VeryNginx/install-lnmp.sh`) silently skips the helper
# build and misreports bundled modules if PWD-based paths are used.
VN_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VN_BUILD="$(git -C "$VN_SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
VN_DIR="${VN_PREFIX}"
BACKUP_DIR="${VN_DIR}/configs/backups"
VN_ADMIN_PASSWORD=""

RED=''; GREEN=''; YELLOW=''; CYAN=''
NC=''; BOLD=''
# ----- helpers -------------------------------------------------------------
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
title() { echo -e "\n${BOLD}━━━ $* ━━━${NC}\n"; }

die() { error "$*"; exit 1; }

confirm() {
  # printf -v instead of eval (same effect, no code-injection smell).
  # EOF/non-interactive stdin: fall back to the default ONCE and stop
  # asking — previously a closed stdin made read fail under set -e with
  # no message at all.
  local prompt="$1" var="$2" default="${3:-n}" val
  while :; do
    printf "%s [y/n] (default: %s): " "$prompt" "$default"
    if ! read -r val; then
      warn "stdin closed — assuming '${default}'"
      val="$default"
    fi
    val="${val:-$default}"
    case "$val" in
      y|Y) printf -v "$var" '%s' "y"; return 0 ;;
      n|N) printf -v "$var" '%s' "n"; return 0 ;;
      *) : ;;   # re-ask on garbage input only
    esac
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

  if command -v rsync >/dev/null 2>&1; then
    # Mirror the source tree so files DELETED upstream don't linger across
    # version upgrades (stale Lua modules keep being loaded — package.path
    # hits them first). Runtime-mutable paths are excluded from deletion.
    rsync -a --delete \
      --exclude "configs/config.json" \
      --exclude "configs/waf-rules.json" \
      --exclude "configs/backups/" \
      --exclude "geoip/" \
      "${src_dir}/verynginx/" "${VN_DIR}/"
    info "Synced files (rsync mirror, runtime data preserved) ✓"
  else
    # No rsync: plain copy (leaves upstream-deleted residue; noted).
    cp -r "${src_dir}/verynginx/"* "${VN_DIR}/"
    info "Copied files ✓ (install rsync for stale-file cleanup on upgrades)"
  fi

  # Write version + git commit info for dashboard display
  if command -v git &>/dev/null && git -C "$src_dir" rev-parse --short HEAD &>/dev/null; then
    git -C "$src_dir" describe --tags --always > "${VN_DIR}/VERSION" 2>/dev/null \
      || echo "dev" > "${VN_DIR}/VERSION"
    git -C "$src_dir" rev-parse HEAD > "${VN_DIR}/COMMIT"
    info "Wrote version info ✓"
  elif [ -f "${src_dir}/VERSION" ]; then
    cp "${src_dir}/VERSION" "${VN_DIR}/VERSION"
    if [ -f "${src_dir}/COMMIT" ]; then
      cp "${src_dir}/COMMIT" "${VN_DIR}/COMMIT"
    else
      echo "unknown" > "${VN_DIR}/COMMIT"
    fi
    info "Wrote version info (from source VERSION file) ✓"
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
  # configs/ holds config.json with security.session_secret — world-readable
  # (755) lets ANY local user forge admin sessions. nginx worker only needs
  # rw via ownership; others get nothing.
  chmod 750 "${VN_DIR}/configs"
  find "${VN_DIR}/configs" -type f -exec chmod 640 {} +

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


# ---- Single source of truth for admin credential hashing -------------------
# OWASP current guidance: PBKDF2-HMAC-SHA256 >= 600,000 iterations (was 12k,
# ~50x below target). Overridable for very low-power boxes. Safe to change:
# the Lua verifier reads the iteration count FROM the stored hash string
# ("p1$iter$salt$hash"), so old and new hashes verify side by side.
VN_PBKDF2_ITER="${VN_PBKDF2_ITER:-600000}"

write_admin_hash() {
  # Caller must export: VN_PASSWORD VN_CONFIG VN_USER
  export VN_PBKDF2_ITER
  local py_script out
  py_script=$(mktemp /tmp/vn_hash.XXXXXX.py)
  cat > "$py_script" << 'PYEOF'
import os, hashlib, hmac, base64, json, secrets

password = os.environ['VN_PASSWORD'].encode('utf-8')
salt = os.urandom(16)
iterations = int(os.environ.get('VN_PBKDF2_ITER', '600000'))

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
  out=$(python3 "$py_script" 2>&1) || { rm -f "$py_script"; die "Failed to generate password hash (python3 required): $out"; }
  rm -f "$py_script"
  [ "$out" = "OK" ] || { warn "Password hash generation failed: $out"; return 1; }
}

  export VN_PASSWORD="$password" VN_CONFIG="$config_file" VN_USER="$default_user"

  write_admin_hash || {
    warn "VeryNginx will auto-generate a password on first start (check error log)"
    return 0
  }
  VN_ADMIN_PASSWORD="$password"
  info "Password set for user '${default_user}'"
  info "Save this password: ${password}"
}

# ----- backup nginx.conf ---------------------------------------------------
VN_BACKUP_KEEP=5

backup_nginx_conf() {
  local bak="${NGINX_CONF}.bak.$(date +%Y%m%d-%H%M%S)"
  cp "$NGINX_CONF" "$bak"
  info "Backup saved: ${bak}"
  # Prune old timestamped backups — unbounded growth across many installs.
  local old
  ls -1t "${NGINX_CONF}".bak.* 2>/dev/null | tail -n +$((VN_BACKUP_KEEP + 1)) | while read -r old; do
    rm -f "$old"
  done || true
}

# ----- inject directives into nginx.conf -----------------------------------

# Locate a directive across the main conf AND one level of include files.
# Sets VN_DIRECTIVE_FILE to the first file containing it. Without this, an
# existing lua_package_path/lua_shared_dict living in an included snippet
# is invisible to the main-conf checks -> we inject a SECOND copy and
# `nginx -t` dies with "duplicate directive".
VN_DIRECTIVE_FILE=""
directive_file() {
  VN_DIRECTIVE_FILE=""
  local pat="$1" inc f exp
  if grep -qE "$pat" "$NGINX_CONF" 2>/dev/null; then
    VN_DIRECTIVE_FILE="$NGINX_CONF"; return 0
  fi
  while IFS= read -r inc; do
    [ -z "$inc" ] && continue
    case "$inc" in /*) f="$inc";; *) f="$(dirname "$NGINX_CONF")/$inc";; esac
    for exp in $f; do            # unquoted: expand glob includes (conf.d/*.conf)
      [ -f "$exp" ] || continue
      if grep -qE "$pat" "$exp" 2>/dev/null; then
        VN_DIRECTIVE_FILE="$exp"; return 0
      fi
    done
  done < <(grep -hoE '^[[:space:]]*include[[:space:]]+[^;]+' "$NGINX_CONF" 2>/dev/null | awk '{print $2}')
  return 1
}

patch_nginx_conf() {
  title "Patching nginx.conf"
  info "Installer build: ${VN_BUILD}"

  backup_nginx_conf

  # 1) upstream block inside http {} (upstream is only valid in http/stream context)
  if ! directive_file 'upstream vn_dynamic_upstream'; then
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
      if grep -q 'upstream vn_dynamic_upstream' "$NGINX_CONF" 2>/dev/null; then
        info "Added upstream vn_dynamic_upstream ✓"
      else
        warn "upstream NOT injected — no '^http {' anchor found in ${NGINX_CONF}"
        echo "    Add manually inside the http block:"
        echo "      upstream vn_dynamic_upstream { balancer_by_lua_block { require(\"plugin.proxy_pass.balancer\").run(); } keepalive 128; }"
      fi
    fi
  else
    info "upstream vn_dynamic_upstream already exists, skipping ✓"
  fi

  # 1b) resolver — OpenResty cosockets (lua-resty-http downloads, webhook
  # dispatch) resolve DNS ONLY via the `resolver` directive; without one,
  # every hostname lookup fails with "no resolver defined". Detect the
  # system resolvers and inject; respect an existing resolver config.
  if grep -qE '^\s*resolver\s' "$NGINX_CONF" 2>/dev/null; then
    info "resolver already configured, skipping ✓"
  else
    # Single awk: filter stubs, cap at 2, join with spaces — NO shell pipes.
    # Under `set -euo pipefail` a pipeline here is a minefield: grep -v
    # returns 1 when everything is filtered out, and head closing early
    # SIGPIPEs its upstream (exit 141) — either kills the install silently.
    local vn_resolvers
    vn_resolvers=$(awk '/^nameserver[ \t]+/ && $2!="127.0.0.53" && $2!="::1" { printf "%s ", $2; if (++n == 2) exit }' /etc/resolv.conf 2>/dev/null || true)
    vn_resolvers="${vn_resolvers% }"
    # NOTE: if-statement, NOT `[ -z ] && x=` — under set -e a false test in a
    # standalone && chain returns 1 and kills the script mid-install.
    if [ -z "$vn_resolvers" ]; then vn_resolvers="8.8.8.8 1.1.1.1"; fi
    # systemd-resolved stub (127.0.0.53) is excluded above: cosocket access
    # to it works, but only on localhost — external-facing boxes are safer
    # with real upstreams; fall back to public resolvers when nothing else.
    if grep -q '^http\s*{' "$NGINX_CONF"; then
      sed -i "/^http\s*{/a\\
    # VeryNginx v2 - resolver for cosocket DNS (GeoIP updater, webhooks)\\
    resolver ${vn_resolvers} valid=300s ipv6=off;" "$NGINX_CONF"
      info "Added resolver (${vn_resolvers}) ✓"
    else
      warn "Cannot find '^http {' at line start in ${NGINX_CONF} — resolver NOT injected"
      echo "    Add manually inside the http {} block:"
      echo "      resolver ${vn_resolvers} valid=300s ipv6=off;"
      echo "    Without it GeoIP updates and webhooks fail: 'no resolver defined'."
    fi
  fi

  # 1c) CA bundle for worker-process TLS verification. lua-resty-http's
  # sslhandshake(verify=true) uses the OpenSSL DEFAULT store, which reads
  # SSL_CERT_FILE / SSL_CERT_DIR from the process env — nginx strips all
  # env by default, so pass it through explicitly (main context `env`).
  local vn_ca
  for vn_ca in /etc/ssl/certs/ca-certificates.crt \
               /etc/pki/tls/certs/ca-bundle.crt \
               /usr/local/share/certs/ca-root-nss.crt; do
    [ -f "$vn_ca" ] && break
    vn_ca=""
  done
  if [ -n "$vn_ca" ]; then
    if grep -q 'SSL_CERT_FILE' "$NGINX_CONF" 2>/dev/null; then
      info "SSL_CERT_FILE already present, skipping ✓"
    else
      sed -i "1i # VeryNginx v2 - CA bundle for cosocket TLS verification\nenv SSL_CERT_FILE=${vn_ca};" "$NGINX_CONF"
      info "Added env SSL_CERT_FILE=${vn_ca} ✓"
    fi
  else
    warn "No CA bundle found — outbound TLS (GeoIP updater) will fail verification"
    echo "    Fix: apt-get install -y ca-certificates   (or yum install -y ca-certificates)"
    echo "    Then re-run this installer."
    echo "    Escape hatch (NOT recommended): set geoip.tls_verify=false in config.json"
  fi

  # 1d) lua cosocket TLS trust chain. CRITICAL: lua-nginx-module's
  # sslhandshake(verify=true) does NOT consult the OpenSSL default store
  # (env SSL_CERT_FILE is irrelevant here) — it ONLY trusts certs loaded via
  # the `lua_ssl_trusted_certificate` directive. Without it every outbound
  # https cosocket fails with X509 err 20 "unable to get local issuer".
  if [ -n "$vn_ca" ]; then
    if grep -q 'lua_ssl_trusted_certificate' "$NGINX_CONF" 2>/dev/null; then
      info "lua_ssl_trusted_certificate already present, skipping ✓"
    else
      sed -i "/^http\s*{/a\\
    # VeryNginx v2 - trust chain for cosocket TLS verification\\
    lua_ssl_trusted_certificate ${vn_ca};\\
    lua_ssl_verify_depth 2;" "$NGINX_CONF"
      info "Added lua_ssl_trusted_certificate (${vn_ca}) ✓"
    fi
  fi

  # 2) add VeryNginx paths to existing lua_package_path inside http block
  local vn_paths="${VN_DIR}/?.lua;${VN_DIR}/lua_script/?.lua;${VN_DIR}/lua_script/module/?.lua"
  local vn_cpath="${VN_DIR}/?.so"
  # If lua_package_path lives in an INCLUDED snippet, injecting into the
  # main conf would create a duplicate directive and fail nginx -t. Merge
  # into whichever file actually holds the directive.
  local lpp_target="$NGINX_CONF"
  if directive_file 'lua_package_path'; then
    lpp_target="$VN_DIRECTIVE_FILE"
    if [ "$lpp_target" != "$NGINX_CONF" ]; then
      info "lua_package_path found in include: ${lpp_target} — merging there"
    fi
  fi
  if [ -n "$lpp_target" ]; then
    # Purge EVERY VeryNginx segment, then merge in the current one — a
    # leftover stale prefix makes Lua load old code/files. The previous
    # regex ([^;"]*verynginx/[^;"]*;;) only removed a segment adjacent to
    # ';;': our own injection is THREE segments, so the two leading ones
    # survived every re-run (unbounded growth) and an old-prefix reinstall
    # kept them forever. Split on ';' and filter instead.
    local tmp_conf="${NGINX_CONF}.vn_tmp.$$"
    # Managed-marker strategy: a line ending in '# vn2-managed' is rebuilt
    # from scratch every run (idempotent under ANY VN_DIR — a literal
    # 'verynginx/' filter cannot recognise custom prefixes like /data/vn2).
    # Unmarked lines are migrated once: drop segments containing the
    # literal 'verynginx/' (legacy default-prefix installs), merge current
    # paths, add the marker.
    awk -v vn="${vn_paths}" '
      /lua_package_path/ && /"/ && !done {
        pre = $0;  sub(/".*$/, "", pre); sub(/[ \t]+$/, "", pre)
        val = $0;  sub(/^[^"]*"/, "", val); sub(/".*$/, "", val)
        out = ""
        if ($0 ~ /vn2-managed/) {
          out = ""
        } else {
          n = split(val, segs, /;/)
          for (i = 1; i <= n; i++) {
            s = segs[i]
            if (s != "" && s !~ /verynginx\//) { out = (out == "" ? s : out ";" s) }
          }
          if (out != "") out = out ";"
        }
        $0 = pre " \"" out vn ";;\" # vn2-managed"
        done = 1
      }
      { print }
    ' "$lpp_target" > "$tmp_conf" && mv "$tmp_conf" "$lpp_target"
    info "Merged VeryNginx paths into existing lua_package_path ✓"
    # also ensure lua_package_cpath exists (ffi.load needs .so search path)
    if ! directive_file 'lua_package_cpath'; then
      sed -i '/^http\s*{/a\    lua_package_cpath "'"${vn_cpath}"';;";' "$NGINX_CONF"
      info "Added lua_package_cpath ✓"
    elif [ "$VN_DIRECTIVE_FILE" != "$NGINX_CONF" ]; then
      warn "lua_package_cpath exists in include (${VN_DIRECTIVE_FILE}) — ensure it covers ${vn_cpath}"
    fi
  else
    # no existing lua_package_path anywhere (main + includes); add it
    sed -i '/^http\s*{/a\
    # VeryNginx v2 - Lua package paths\
    lua_package_path "'"${vn_paths}"';;";\
    lua_package_cpath "'"${vn_cpath}"';;";' "$NGINX_CONF"
    if grep -q 'lua_package_path' "$NGINX_CONF" 2>/dev/null; then
      info "Added lua_package_path ✓"
    else
      warn "lua_package_path NOT injected — no '^http {' anchor in ${NGINX_CONF}; add manually"
    fi
  fi

  # 3) shared dicts + init blocks inside http {}
  # PER-DICT injection: a single marker ('grep vn_config -> skip all') meant
  # upgrades from versions lacking newer dicts never received them, and init
  # crashed on ngx.shared.<name> == nil. Each dict/init directive below is
  # checked and injected independently. List must stay in sync with
  # verynginx/nginx_conf/in_http_block.conf (note: metrics_labeled was also
  # missing from this installer block entirely).
  inject_after_http() {
    sed -i "/^http[ \t]*{/a\\
$1" "$NGINX_CONF"
  }
  local dentry dname dsize added_dicts=""
  for dentry in \
    "vn_config:2m" "vn_locks:256k" "vn_rate_limit:4m" "vn_session:2m" \
    "statistics:20m" "metrics:10m" "metrics_labeled:16m" "healthcheck:10m" \
    "dns_cache:4m" "frequency_limit:10m" "ip_reputation:16m"; do
    dname="${dentry%%:*}"; dsize="${dentry##*:}"
    if ! directive_file "lua_shared_dict[[:space:]]+${dname}[[:space:]]"; then
      inject_after_http "\
    lua_shared_dict ${dname} ${dsize};"
      added_dicts="$added_dicts ${dname}"
    fi
  done
  if [ -n "$added_dicts" ]; then
    info "Added shared dict(s):${added_dicts} ✓"
  else
    info "Shared dicts already present, skipping ✓"
  fi
  if ! directive_file '^[[:space:]]*lua_code_cache'; then
    inject_after_http "    lua_code_cache on;"
    info "Added lua_code_cache ✓"
  fi
  if ! directive_file 'init_by_lua_block'; then
    inject_after_http "\
    # VeryNginx v2 - main process initialization\
    init_by_lua_block {\
        require(\"core.init\").init()\
    }"
    info "Added init_by_lua_block ✓"
  fi
  if ! directive_file 'init_worker_by_lua_block'; then
    inject_after_http "\
    # VeryNginx v2 - worker-level timers\
    init_worker_by_lua_block {\
        require(\"core.init\").init_worker()\
    }"
    info "Added init_worker_by_lua_block ✓"
  fi

  # WebSocket connection upgrade (map must live at http level)
  if ! directive_file 'map[[:space:]]+\$http_upgrade'; then
    inject_after_http "\\
    # VeryNginx v2 - WebSocket connection upgrade\\
    map \\$http_upgrade \\$connection_upgrade {\\
        default upgrade;\\
        '' close;\\
    }"
    info "Added WebSocket upgrade map ✓"
  fi

  # 4) server block directives
  # ALWAYS re-inject: a previous install may have left handlers pointing at
  # a stale prefix (marker alone proves nothing about WHERE they point).
  replace_server_block


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

# NOTE: no early-exit on a marker. A previous install may have left the
# marker in place while pointing at a DIFFERENT (now stale) prefix — skipping
# then keeps serving old files forever (field-reported: 7-day-cached stale
# static location survived every reinstall). Always clean + re-inject with
# the CURRENT vn_dir; the cleanup below is generation-agnostic.

# --- Locate an HTTP server{} block robustly -------------------------------
# text.find('server {') was a literal match: it hit COMMENTED-OUT blocks,
# quoted strings, and stream{} upstream servers; brace counting ignored
# comments/strings entirely. Mask comments+strings (length-preserving), then
# scan structurally. Masked offsets map 1:1 onto the original text.
def mask_comments_strings(t):
    out=[]; i=0; n=len(t); q=None; h=False
    while i < n:
        c = t[i]
        if h:
            out.append('\n' if c=='\n' else ' ')
            if c=='\n': h=False
            i += 1; continue
        if q:
            if c == '\\':
                out.append('  '); i += 2; continue
            out.append(' ')
            if c == q: q = None
            i += 1; continue
        if c == '#':
            h = True; out.append(' '); i += 1; continue
        if c in ('"', "'"):
            q = c; out.append(' '); i += 1; continue
        out.append(c); i += 1
    return ''.join(out)

def match_brace(t, open_idx):
    depth = 0
    for j in range(open_idx, len(t)):
        if t[j] == '{': depth += 1
        elif t[j] == '}':
            depth -= 1
            if depth == 0: return j
    return -1

def find_named_blocks(t, name):
    res = []
    for m in re.finditer(r'\b' + name + r'\b[ \t]*\{', t):
        ob = m.end() - 1
        cb = match_brace(t, ob)
        if cb != -1: res.append((m.start(), ob, cb))
    return res

masked = mask_comments_strings(text)
http_spans   = find_named_blocks(masked, 'http')
stream_spans = find_named_blocks(masked, 'stream')

candidates = []
for m in re.finditer(r'\bserver\b[ \t]*\{', masked):
    ob = m.end() - 1
    cb = match_brace(masked, ob)
    if cb == -1: continue
    # A server{} inside stream{} is L4 proxying, not an HTTP vhost — skip.
    if any(a <= m.start() <= c for a, b, c in stream_spans): continue
    candidates.append((m.start(), ob, cb))

chosen = None
for ha, hob, hcb in http_spans:
    for cand in candidates:
        if ha < cand[0] < hcb:
            chosen = cand; break
    if chosen: break
if not chosen and candidates:
    chosen = candidates[0]

if not chosen:
    # LNMP-style conf: all vhosts live in include files. Degrade instead of
    # dying AFTER nginx has been fully configured.
    print("NO_SERVER")
    sys.exit(0)

brace_pos = chosen[1]
server_end = chosen[2]
server_inner = text[brace_pos+1:server_end]
after = text[server_end:]

# --- Clean old VeryNginx Lua handlers from the server block ---
# (handles location-level AND server-level, from ANY previous install
# prefix — not just the current one; a stale prefix's handlers must go too)
# [ \t] not \s: a greedy \s* after ';' swallows the NEWLINE plus the next
# line's indentation, so the following line loses its line-start anchor '^'
# and escapes matching entirely (two consecutive include/lua lines -> only
# the first removed). Whitespace around directives never spans lines.
lua_pattern = re.compile(
    r'^[ \t]*(rewrite|access|log)_by_lua_file\s+\S*on_(?:rewrite|access|log)\.lua[ \t]*;[ \t]*$',
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

# Remove manual include lines pointing at our server-block snippet (any
# prefix). Users following the DO_PATCH=n guidance added
#   include /path/in_server_block.conf;
# by hand; if kept alongside the handlers we inject here, nginx ends up
# with DUPLICATE server-level lua handlers and fails `nginx -t`.
server_inner = re.sub(
    r'^[ \t]*include[ \t]+[^;\n]*in_server_block\.conf[ \t]*;[ \t]*\n?',
    '',
    server_inner,
    flags=re.MULTILINE
)

# Collapse runs of blank lines left by directive removal
server_inner = re.sub(r'\n{3,}', '\n\n', server_inner)

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
    + "'self'; "
    + "script-src 'self'; "
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

  if ! command -v python3 >/dev/null 2>&1; then
    rm -f "$py_script"
    warn "python3 unavailable — cannot rewrite server block automatically"
    echo "    Finish with ONE line inside each server{} you want protected:"
    echo "      include ${VN_DIR}/nginx_conf/in_server_block.conf;"
    return 0
  fi
  local out
  out=$(python3 "$py_script" "$NGINX_CONF" "$VN_DIR" 2>&1) || { rm -f "$py_script"; die "Failed to patch server block: $out"; }
  rm -f "$py_script"

  if [ "$out" = "OK" ]; then
    info "Server block patched with server-level VeryNginx handlers ✓"
    info "→ WAF now protects all requests in this server block"
    info "→ Dashboard: http://your-ip/verynginx/index.html"
  elif [ "$out" = "ALREADY_PRESENT" ]; then
    info "Server-level VeryNginx handlers already present, skipping ✓"
  elif [ "$out" = "NO_SERVER" ]; then
    # Pure vhost-include layout: don't die this late — tell the user how to
    # finish manually. Everything else (paths/dicts/upstream) already landed.
    warn "No server{} block in ${NGINX_CONF} (vhosts live in include files?)"
    echo "    Finish with ONE line inside each server{} you want protected:"
    echo "      include ${VN_DIR}/nginx_conf/in_server_block.conf;"
    echo "    then reload nginx. Dashboard: http://your-ip/verynginx/index.html"
  else
    die "Server block patch failed: $out"
  fi
}

# ----- nginx test & reload -------------------------------------------------
reload_nginx() {
  title "Testing nginx configuration"

  if "$WEB_SERVER_BIN" -t 2>&1; then
    info "nginx configuration test passed ✓"
    # Unit name is NOT always 'nginx' (source/openresty builds often use
    # 'openresty'); detect rather than assume.
    local vn_unit=""
    if command -v systemctl >/dev/null 2>&1; then
      local _u
      for _u in nginx openresty; do
        if systemctl cat "${_u}.service" >/dev/null 2>&1; then vn_unit="$_u"; break; fi
      done
    fi
    if [ -n "$vn_unit" ]; then
      if svc_is_active "$vn_unit" 2>/dev/null; then
        if systemctl reload "$vn_unit" 2>/dev/null; then
          info "${vn_unit} reloaded ✓"
        elif systemctl restart "$vn_unit" 2>/dev/null; then
          warn "reload failed — performed full restart of ${vn_unit} instead ✓"
        else
          warn "FAILED to reload/restart ${vn_unit} — do it manually:"
          echo "      systemctl restart ${vn_unit}"
        fi
      else
        warn "${vn_unit} is not running. Start it with: systemctl start ${vn_unit}"
      fi
    else
      # No systemd unit (sysv/source build): signal-based reload.
      if "$WEB_SERVER_BIN" -s reload 2>/dev/null; then
        info "reload signal sent via '${WEB_SERVER_BIN} -s reload' ✓"
      else
        warn "'${WEB_SERVER_BIN} -s reload' failed — reload manually"
      fi
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

  # Post-install self-check: dashboard asset serving. Catches the classic
  # reinstall failure where the injected location snippet landed in a server
  # block other than the one actually serving traffic (LNMP vhost includes).
  # Best-effort only — never fails the install.
  if command -v curl >/dev/null 2>&1 && [ -n "$NGINX_CONF" ] && [ -f "$NGINX_CONF" ]; then
    local chk_port chk_code
    # Probe EVERY listen port of the first server{} block (plain-HTTP only:
    # an ssl-only listener answers a cleartext probe with a handshake reset,
    # which curl reports as code 000 — not a real failure signal). First port
    # that yields ANY HTTP status wins; fall back to global listen scan.
    local ports p
    # NOTE: `|| true` on every pipeline + if-statements (never `[ ] && =`):
    # grep with no match exits 1 and pipefail turns that into a script-wide
    # abort INSIDE the very warning branches this code exists to reach.
    ports=$(awk '/server[ \t]*\{/{f=1} f&&$1=="listen"&&$0!~/ssl/{print} f&&/^[ \t]*\}/{exit}' \
      "$NGINX_CONF" 2>/dev/null | grep -oE '[0-9]{2,5}' | sort -un || true)
    if [ -z "$ports" ]; then
      ports=$(grep -oP 'listen\s+\S*?:?\K[0-9]+' "$NGINX_CONF" 2>/dev/null | sort -un || true)
    fi
    if [ -z "$ports" ]; then ports="80"; fi
    chk_port=""; chk_code="000"
    sleep 1
    for p in $ports; do
      local c
      # NOTE: `|| true`, not `|| echo 000` — curl -w already prints 000 on
      # connect failure; appending another yields "000\n000" which passes
      # the != "000" test and misreports a dead port as serving.
      c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
        -H 'Host: localhost' "http://127.0.0.1:${p}/verynginx/static/style.css" 2>/dev/null || true)
      if [ -n "$c" ] && [ "$c" != "000" ]; then chk_port="$p"; chk_code="$c"; break; fi
    done
    if [ "$chk_code" = "200" ]; then
      info "Self-check: dashboard style.css served ✓ (port ${chk_port})"
    elif [ "$chk_port" = "" ]; then
      # No port answered at all — connection-level problem, NOT a snippet one.
      warn "Self-check: no HTTP response on probed ports ($(echo $ports | tr '\n' ' '))"
      echo "    curl could not connect on loopback. Likely causes:"
      echo "      - nginx not running/reloaded yet (systemctl status nginx)"
      echo "      - server blocks bind to specific external IPs only"
      echo "      - all listeners are ssl-only (probe speaks plain HTTP)"
      echo "    The Lua router serves dashboard assets regardless once traffic flows."
    else
      warn "Self-check: GET /verynginx/static/style.css returned ${chk_code} on port ${chk_port} (expected 200)"
      echo "    The static snippet may be missing from the SERVER BLOCK THAT SERVES YOUR TRAFFIC."
      echo "    Patched file : ${NGINX_CONF} (first server{} block)"
      echo "    Check inside the vhost you actually browse:"
      echo "      grep -n 'location /verynginx/static/' \$(nginx -T 2>/dev/null | grep -oE '/[^ ]+\.conf' | sort -u) 2>/dev/null"
      echo "    Note: since this version the Lua router ALSO serves dashboard assets,"
      echo "    so a plain 'systemctl restart nginx' usually fixes 404s even without the snippet."
    fi
    # Serving-drift check: whatever nginx ACTUALLY returns for index.html must
    # carry the same integrity pin as the installed file. A mismatch means a
    # foreign/stale dashboard copy is being served (second docroot, manual
    # edits, parallel tooling) — the #1 cause of irreproducible panel breakage.
    local serve_pin local_pin
    serve_pin=$(curl -s --max-time 5 -H 'Host: localhost' \
      "http://127.0.0.1:${chk_port}/verynginx/index.html" 2>/dev/null \
      | grep -o 'vue\.global\.prod\.js" integrity="[^"]*' | head -1 || true)
    local_pin=$(grep -o 'vue\.global\.prod\.js" integrity="[^"]*' \
      "${VN_DIR}/dashboard/index.html" 2>/dev/null | head -1 || true)
    if [ -n "$local_pin" ]; then
      if [ -z "$serve_pin" ]; then
        warn "Self-check: served /verynginx/index.html has NO vue integrity pin (foreign copy?)"
        echo "    nginx is not serving ${VN_DIR}/dashboard — find the real docroot:"
        echo "      nginx -T 2>/dev/null | grep -n 'verynginx\\|alias\\|root'"
      elif [ "$serve_pin" != "$local_pin" ]; then
        warn "Self-check: SERVED index.html pin differs from installed copy — drift!"
        echo "    served : ${serve_pin}"
        echo "    local  : ${local_pin}"
        echo "    Another dashboard copy is being served (stale dir / manual edit)."
        echo "    Locate it: nginx -T 2>/dev/null | grep -n 'alias\\|root' ; then re-deploy THERE."
      else
        info "Self-check: served index.html matches installed copy ✓"
      fi
    fi
    # Drift check: the integrity pin inside index.html must equal the
    # sha384 of the INSTALLED vue.global.prod.js. Comparing against the pin
    # (not the vendored copy) catches the field failure mode where BOTH
    # copies drifted identically (editor save / transfer appended a byte):
    # browser then blocks the script with an integrity error.
    local vue_file="${VN_DIR}/dashboard/vue.global.prod.js"
    if [ -f "$vue_file" ] && [ -f "${VN_DIR}/dashboard/index.html" ]; then
      local vue_pin vue_hash
      vue_pin=$(grep -o 'vue\.global\.prod\.js" integrity="sha384-[^"]*' \
        "${VN_DIR}/dashboard/index.html" 2>/dev/null | head -1 | sed 's/.*sha384-//' || true)
      vue_hash=$(openssl dgst -sha384 -binary "$vue_file" 2>/dev/null | openssl base64 -A 2>/dev/null || true)
      if [ -n "$vue_pin" ] && [ -n "$vue_hash" ] && [ "$vue_pin" != "$vue_hash" ]; then
        warn "Self-check: index.html SRI pin != installed vue.global.prod.js (${vue_file})"
        echo "    The vendored Vue file differs from the pinned digest — likely edited/corrupted"
        echo "    in the source tree (e.g. an appended trailing byte). Fix:"
        echo "      cd <repo> && git checkout -- verynginx/dashboard/vue.global.prod.js"
        echo "      ./install-lnmp.sh"
      else
        info "Self-check: vue.global.prod.js matches its SRI pin ✓"
      fi
    fi
  fi

  local host_ip=""
  # 'ip route get' field position breaks when there is no direct gateway
  # route (yields http:///verynginx/). Try robust sources in order.
  host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  if [ -z "$host_ip" ]; then
    host_ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '$2!="lo"{print $4; exit}' | cut -d/ -f1)
  fi
  if [ -z "$host_ip" ]; then
    host_ip=$(ip -4 route get 1 2>/dev/null | head -1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
  fi
  [ -z "$host_ip" ] && host_ip="<your-server-ip>"

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
   echo "       $0 reset-password [PASSWORD]"
   echo ""
   echo "Options:"
   echo "  -h, --help         Show this help message"
   echo ""
   echo "Commands:"
   echo "  reset-password     Set admin password (random if omitted)"
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
  # Usage: reset-password [PASSWORD]
  #   If PASSWORD is given, use it; otherwise prompt (empty = random).
  local config_file="${VN_DIR}/configs/config.json"
  if [ ! -f "$config_file" ]; then
    die "config.json not found at $config_file. Run install first."
  fi

  local password="$1"

  if [ -z "$password" ]; then
    echo ""
    echo "  Reset admin password for user 'verynginx'"
    read -rsp "  Enter new password (min 6 chars, leave empty for random): " password
    echo
  fi

  if [ -z "$password" ]; then
    password=$(dd if=/dev/urandom bs=12 count=1 2>/dev/null | base64 | tr -dc 'A-Za-z0-9')
    password="${password:0:12}"
    echo "  Generated password: ${password}"
  elif [ ${#password} -lt 6 ]; then
    die "Password too short (min 6 chars)"
  fi

  export VN_PASSWORD="$password" VN_CONFIG="$config_file" VN_USER="verynginx"

  write_admin_hash

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
    "/usr/local/lib/lua/5.1/resty/core.lua"
    "/usr/local/lib/lua/5.1/resty/core.so"
    "/usr/share/lua/5.1/resty/core.lua"
    "/usr/share/lua/5.1/resty/core.so"
    "/usr/local/share/luajit-2.1.*/resty/core.lua"
  )
  local lrucache_files=(
    "/usr/local/share/lua/5.1/resty/lrucache.lua"
    "/usr/local/share/lua/5.1/resty/lrucache.so"
    "/usr/local/lib/lua/5.1/resty/lrucache.lua"
    "/usr/local/lib/lua/5.1/resty/lrucache.so"
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
  if [ -f "${VN_SCRIPT_DIR}/verynginx/table/isarray.lua" ] && [ -f "${VN_SCRIPT_DIR}/verynginx/table/nkeys.lua" ]; then
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
  local helper_src="${VN_SCRIPT_DIR}/helper"
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
  # Re-install safety (ETXTBSY): an older firewall-helper may still be running
  # from a previous installation — cp over a live executable fails with
  # "Text file busy". Stop the units first, then replace via tmp+rename
  # (rename(2) works even if something still holds the old inode open).
  local _helper_was_active=0
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet firewall-helper.service 2>/dev/null; then
      _helper_was_active=1
      systemctl stop firewall-helper.socket 2>/dev/null || true
      systemctl stop firewall-helper.service 2>/dev/null || true
    fi
  fi

  if ! cp "${helper_src}/firewall-helper" "$FIREWALL_HELPER_BIN" 2>/dev/null; then
    local _tmp_bin="${FIREWALL_HELPER_BIN}.install.$$"
    cp "${helper_src}/firewall-helper" "$_tmp_bin" \
      || { warn "Failed to stage $FIREWALL_HELPER_BIN — kernel IP blocking will be unavailable"; return 0; }
    chmod 755 "$_tmp_bin"
    mv -f "$_tmp_bin" "$FIREWALL_HELPER_BIN"
  fi
  chmod 755 "$FIREWALL_HELPER_BIN"
  info "Installed: $FIREWALL_HELPER_BIN ✓"

  # Create socket directory
  mkdir -p "$FIREWALL_HELPER_DIR"
  chmod 755 "$FIREWALL_HELPER_DIR"
  info "Socket directory: $FIREWALL_HELPER_DIR ✓"

  # Install systemd units if systemd is present
  if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
    info "Installing systemd socket activation units..."
    _VN_GROUP_JOINED=0

    # Socket access control: the helper holds CAP_NET_ADMIN and has NO
    # per-request auth — a world-writable socket means ANY local user can
    # add/drop nftables rules. 0660 + dedicated group whose member is the
    # web-server user (the only legitimate client).
    local vn_group="verynginx"
    if ! getent group "$vn_group" >/dev/null 2>&1; then
      groupadd -r "$vn_group" 2>/dev/null || true
    fi
    local vn_web_user
    vn_web_user=$(grep -m1 '^\s*user\s' "$NGINX_CONF" 2>/dev/null | awk '{print $2}' | awk -F';' '{print $1}')
    if [ -n "$vn_web_user" ] && id "$vn_web_user" >/dev/null 2>&1; then
      if ! id -nG "$vn_web_user" 2>/dev/null | tr ' ' '\n' | grep -qx "$vn_group"; then
        usermod -aG "$vn_group" "$vn_web_user" 2>/dev/null || true
        info "Added ${vn_web_user} to group ${vn_group} ✓"
        _VN_GROUP_JOINED=1
      fi
    else
      warn "Could not detect nginx worker user — add it manually: usermod -aG ${vn_group} <user>"
      _VN_GROUP_JOINED=1
    fi

    # Write socket unit
    cat > /etc/systemd/system/firewall-helper.socket <<SOCKUNIT
[Unit]
Description=VeryNginx Firewall Helper Socket
Before=nginx.service

[Socket]
ListenStream=${FIREWALL_HELPER_SOCKET}
SocketMode=0660
Group=${vn_group}
DirectoryMode=0750

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
    systemctl enable firewall-helper.service
    systemctl start firewall-helper.socket 2>/dev/null || true
    # Re-install path: we stopped a running helper before replacing the
    # binary — restart it so the NEW build is what socket activation uses.
    if [ "$_helper_was_active" = "1" ]; then
      systemctl start firewall-helper.socket 2>/dev/null || true
      systemctl restart firewall-helper.service 2>/dev/null || true
    fi
    info "systemd units installed and started ✓"
    if systemctl is-active --quiet firewall-helper.socket 2>/dev/null; then
      local sock_mode
      sock_mode=$(stat -c '%a' "${FIREWALL_HELPER_SOCKET}" 2>/dev/null || echo "?")
      if [ "$sock_mode" = "660" ]; then
        info "socket permission 0660 group=${vn_group:-verynginx} ✓"
      else
        warn "socket mode is ${sock_mode}, expected 660 — check Group=/SocketMode= in firewall-helper.socket"
      fi
      info "firewall-helper.socket is active ✓"
      if [ "${_VN_GROUP_JOINED:-0}" = "1" ]; then
        warn "Group membership changed: FULLY restart nginx for workers to pick it up"
        echo "      (a reload/HUP does NOT refresh supplementary groups)"
      fi
    else
      warn "firewall-helper.socket failed to start — check: systemctl status firewall-helper.socket"
    fi
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
        reset_admin_password "${2:-}"
        exit 0
        ;;
    esac
  done

  require_root
  detect_web_server

  # python3 powers config patching (replace_server_block) and password
  # hashing. The password step is SKIPPED when a password is already
  # configured, which used to let a python3-less box sail through every sed
  # injection and die mid-patch at the server-block rewrite — nginx.conf
  # left half-modified and never nginx -t'd. Fail BEFORE touching anything.
  if ! command -v python3 >/dev/null 2>&1; then
    die "python3 is required but not found. Install it first:
    apt-get install -y python3   |   yum install -y python3"
  fi

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
    if ! probe_nftables_capabilities; then
      warn "Skipping Firewall Helper installation — nftables unavailable"
      warn "Kernel IP blocking disabled; panel/WAF/proxy remain fully functional"
    else
      install_firewall_helper
    fi
  else
    info "Skipping Firewall Helper installation"
    info "You can install it later by re-running install-lnmp.sh"
  fi

  show_summary
}

main "$@"

