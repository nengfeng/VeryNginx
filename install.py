#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2026-06-24
# @Author  : VeryNginx v2
# @Disc    : install VeryNginx v2 (support python 2.x and 3.x)

import os
import sys
import getopt
import filecmp
import shutil
import hashlib
import base64
import re

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

openresty_pkg_url = 'https://openresty.org/download/openresty-1.31.1.1.tar.gz'
openresty_pkg = 'openresty-1.31.1.1.tar.gz'
# sha256 of the tarball, computed over the artifact served by
# openresty.org at pin time (gzip integrity verified). Supply-chain
# guard: a tampered or truncated tarball must abort the install.
openresty_pkg_sha256 = '65b78baadd3f0984055de89bf13f4a1932e5bfe9c31932037a134ea2b1a0ce42'

VN_PREFIX = '/opt/verynginx'

work_path = os.getcwd()

# ---------------------------------------------------------------------------
# Path substitution: replace default prefix with custom one in installed files
# ---------------------------------------------------------------------------

def verify_dashboard_sri():
    """Drift check: index.html pins vue.global.prod.js by SHA-384 over the raw
    bytes. A checkout with CRLF line endings (files checked out before
    .gitattributes declared eol=lf, e.g. on Windows) breaks the hash and the
    browser silently blocks the script — the dashboard white-screens with no
    error text. install.py deploys the working tree byte-for-byte, so catch
    the drift here (same check install-lnmp.sh runs)."""
    dashboard = VN_PREFIX + '/dashboard'
    index_path = dashboard + '/index.html'
    vue_path = dashboard + '/vue.global.prod.js'
    if not (os.path.exists(index_path) and os.path.exists(vue_path)):
        return
    with open(index_path, 'r', encoding='utf-8', errors='replace') as f:
        index_html = f.read()
    m = re.search(r'vue\.global\.prod\.js" integrity="sha384-([^"]+)', index_html)
    if not m:
        return
    digest = hashlib.sha384(open(vue_path, 'rb').read()).digest()
    actual = base64.b64encode(digest).decode()
    if actual != m.group(1):
        print('### WARNING: index.html SRI pin != installed vue.global.prod.js')
        print('###   The dashboard will white-screen (browser blocks the script).')
        print('###   Fix in the source tree, then reinstall:')
        print('###     git checkout -- verynginx/dashboard/vue.global.prod.js')


def fix_prefix(path):
    if VN_PREFIX == '/opt/verynginx':
        return
    if not os.path.isfile(path):
        return
    with open(path, 'r') as f:
        content = f.read()
    if '/opt/verynginx' not in content:
        return
    content = content.replace('/opt/verynginx', VN_PREFIX)
    with open(path, 'w') as f:
        f.write(content)

# ---------------------------------------------------------------------------
# Install OpenResty
# ---------------------------------------------------------------------------

def install_openresty():
    if os.path.exists(VN_PREFIX + '/VeryNginx/VeryNginx') == True:
        print("Seems that a old version of VeryNginx was installed in " + VN_PREFIX + "/...")
        print("Before install, please delete it and backup the configs if you need.")
        sys.exit(1)

    print('### makesure the work directory is clean')
    exec_sys_cmd('rm -rf ' + openresty_pkg.replace('.tar.gz',''))

    down_flag = True
    if os.path.exists('./' + openresty_pkg):
        ans = ''
        while ans not in ['y','n']:
            ans = common_input(' Found %s in current directory, use it?(y/n)' % openresty_pkg)
        if ans == 'y':
            down_flag = False

    if down_flag == True:
        print('### start download openresty package...')
        exec_sys_cmd('rm -rf ' + openresty_pkg)
        exec_sys_cmd('wget ' + openresty_pkg_url)
    else:
        print('### use local openresty package...')

    # Supply-chain check: verify the tarball before it is built as root.
    # VN_SKIP_CHECKSUM=1 overrides (air-gapped mirrors etc.) — at your own risk.
    expected = openresty_pkg_sha256
    digest = hashlib.sha256(open('./' + openresty_pkg, 'rb').read()).hexdigest()
    if digest != expected and os.environ.get('VN_SKIP_CHECKSUM') != '1':
        print('### ERROR: openresty tarball sha256 mismatch')
        print('###   expected: ' + expected)
        print('###   actual  : ' + digest)
        print('###   The download may be tampered with or truncated. Aborting.')
        sys.exit(1)

    print('### release the package ...')
    exec_sys_cmd('tar -xzf ' + openresty_pkg)

    print('### configure openresty ...')
    os.chdir(openresty_pkg.replace('.tar.gz',''))
    exec_sys_cmd(
        './configure --prefix=' + VN_PREFIX + '/openresty '
        '--user=nginx --group=nginx '
        '--with-http_v2_module --with-http_sub_module '
        '--with-http_stub_status_module --with-luajit '
        '--with-pcre-jit '
        '--with-stream --with-stream_ssl_module'
    )

    print('### compile openresty ...')
    exec_sys_cmd('make')

    print('### install openresty ...')
    exec_sys_cmd('make install')

# ---------------------------------------------------------------------------
# Install / Update VeryNginx
# ---------------------------------------------------------------------------

def install_verynginx():
    print('### copy VeryNginx files ...')
    os.chdir(work_path)

    if os.path.exists(VN_PREFIX + '/') == False:
        exec_sys_cmd('mkdir -p ' + VN_PREFIX)

    # Copy v2 source code (configs/config.json is gitignored, not overwritten)
    exec_sys_cmd('cp -r -f ./verynginx/. ' + VN_PREFIX + '/')
    verify_dashboard_sri()

    # Fix hardcoded /opt/verynginx paths if prefix is custom
    if VN_PREFIX != '/opt/verynginx':
        for root, dirs, files in os.walk(VN_PREFIX):
            for f in files:
                if f.endswith('.conf') or f.endswith('.lua'):
                    fix_prefix(os.path.join(root, f))

    # Bootstrap config: create config.json from template if not exists
    config_json = VN_PREFIX + '/configs/config.json'
    config_default = VN_PREFIX + '/configs/config.default.json'
    if not os.path.exists(config_json):
        if os.path.exists(config_default):
            print('### bootstrap config: copy config.default.json -> config.json')
            shutil.copyfile(config_default, config_json)
            print('### IMPORTANT: edit config.json and set admin password_hash before use')
        else:
            print('### WARNING: no config.default.json found, will use built-in defaults')

    # Ensure backups directory exists
    backups_dir = VN_PREFIX + '/configs/backups'
    if not os.path.exists(backups_dir):
        os.makedirs(backups_dir)

    # Deploy the pinned upgrade helper: bake THIS tree's commit as the pin.
    # The trust anchor for future upgrades is the installed copy — repo
    # writers cannot retroactively change a pin that shipped at install time.
    tools_src = './tools/upgrade.sh'
    if os.path.exists(tools_src):
        if not os.path.isdir(VN_PREFIX + '/tools'):
            os.makedirs(VN_PREFIX + '/tools')
        pin = 'unknown'
        try:
            pin = os.popen('git rev-parse HEAD').read().strip() or 'unknown'
        except Exception:
            pass
        with open(tools_src, 'r', encoding='utf-8') as f:
            script = f.read()
        script = re.sub(r'^VN_PINNED_COMMIT=.*$',
                        'VN_PINNED_COMMIT="%s"' % pin, script, count=1, flags=re.M)
        with open(VN_PREFIX + '/tools/upgrade.sh', 'w', encoding='utf-8') as f:
            f.write(script)
        exec_sys_cmd('chmod 750 ' + VN_PREFIX + '/tools/upgrade.sh')
        print('### deployed pinned upgrade helper (anchor: %s)' % pin)

    # Copy nginx.conf to openresty (if openresty is installed and has default config)
    openresty_conf = VN_PREFIX + '/openresty/nginx/conf/nginx.conf'
    openresty_conf_default = VN_PREFIX + '/openresty/nginx/conf/nginx.conf.default'
    if os.path.exists(VN_PREFIX + '/openresty') == True:
        if os.path.exists(openresty_conf_default) and filecmp.cmp(openresty_conf, openresty_conf_default, False) == True:
            print('### copy nginx config file to openresty')
            exec_sys_cmd('cp -f ./nginx.conf ' + openresty_conf)
        elif not os.path.exists(openresty_conf_default):
            print('### copy nginx config file to openresty (first install)')
            exec_sys_cmd('cp -f ./nginx.conf ' + openresty_conf)
        # Fix paths in nginx.conf if prefix is custom
        fix_prefix(openresty_conf)
    else:
        print('### openresty not found, so not copying nginx.conf')

    # Set permissions for config storage. configs/ holds config.json with
    # security.session_secret (HMAC key for admin sessions) and
    # admin[].password_hash — world-readable (755) lets ANY local user forge
    # admin sessions offline. Mirror install-lnmp.sh: 750/640, owned by the
    # nginx user so only the service (and root) can read them.
    print('### create nginx user/group if not exist')
    exec_sys_cmd('id -u nginx > /dev/null 2>&1 || useradd -r -s /sbin/nologin nginx', accept_failed=True)
    exec_sys_cmd('chown -R nginx:nginx ' + VN_PREFIX + '/configs')
    exec_sys_cmd('chmod 750 ' + VN_PREFIX + '/configs')
    exec_sys_cmd('find ' + VN_PREFIX + '/configs -type f -exec chmod 640 {} +')

def update_verynginx():
    print('### WARNING: update will keep existing config.json')
    print('### Backup your config:\n    cp ' + VN_PREFIX + '/configs/config.json ~/')
    ans = common_input('Continue? (y/n): ')
    if ans != 'y':
        print('Update cancelled.')
        return

    # Backup config
    config_json = VN_PREFIX + '/configs/config.json'
    config_backup = VN_PREFIX + '/configs/config.json.update_backup'
    if os.path.exists(config_json):
        shutil.copyfile(config_json, config_backup)
        print('### backup saved to ' + config_backup)

    install_verynginx()

    # Restore config
    if os.path.exists(config_backup):
        shutil.copyfile(config_backup, config_json)
        print('### config restored from backup')

    print('### update complete')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def exec_sys_cmd(cmd, accept_failed=False):
    print(cmd)
    ret = os.system(cmd)
    if ret == 0:
        return ret
    else:
        if accept_failed == False:
            print('*** The installing stopped because something was wrong')
            exit(1)
        else:
            return False

def common_input(s):
    if sys.version_info[0] == 3:
        return input(s)
    else:
        return raw_input(s)

def safe_pop(l):
    if len(l) == 0:
        return None
    else:
        return l.pop(0)

def hash_password(password, iterations=600000):
    """Generate a PBKDF2-HMAC-SHA256 hash compatible with VeryNginx v2.

    Same algorithm as core/password_hash.lua.
    Format: p1$iterations$salt_b64$hash_b64

    Default 600000 iterations (OWASP current guidance). Keep in sync with
    core/password_hash.lua DEFAULT_ITERATIONS and install-lnmp.sh
    VN_PBKDF2_ITER so all install entry points produce equally strong hashes.
    """
    import hashlib
    import hmac
    import base64
    import os
    import sys

    salt = os.urandom(16)
    if isinstance(password, str):
        password = password.encode('utf-8')

    # U_1 = HMAC(password, salt || INT(1))  -- INT(1) = 4-byte big-endian
    init_msg = salt + b'\x00\x00\x00\x01'
    u = hmac.new(password, init_msg, 'sha256').digest()

    # Result starts as U_1, then XOR with U_2..U_iterations
    if sys.version_info[0] == 3:
        result = bytearray(u)
        for i in range(2, iterations + 1):
            u = hmac.new(password, u, 'sha256').digest()
            for j, b in enumerate(u):
                result[j] ^= b
        result = bytes(result)
    else:
        # Python 2: bytearray doesn't support enumerate iteration well
        import array
        result = array.array('B', u)
        for i in range(2, iterations + 1):
            u = hmac.new(password, u, 'sha256').digest()
            u_arr = array.array('B', u)
            for j in range(len(result)):
                result[j] ^= u_arr[j]
        result = bytes(result)

    def b64enc(data):
        enc = base64.b64encode(data)
        if isinstance(enc, bytes):
            return enc.decode('ascii')
        return enc

    return 'p1${}${}${}'.format(
        iterations,
        b64enc(salt),
        b64enc(result)
    )

def show_help_and_exit():
    help_doc = '''usage: install.py [--prefix /opt/verynginx] <cmd> <args> ...

install cmds and args:
    install
        all        :  install verynginx and openresty (default)
        openresty  :  install openresty only
        verynginx  :  install verynginx only
    update
        verynginx  :  update the installed verynginx
    hash-password <password>
                  :  generate a password hash for config.json (no luarocks needed)
    '''
    print(help_doc)
    exit()

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], '', ['prefix='])
    for o, a in opts:
        if o == '--prefix':
            VN_PREFIX = a.rstrip('/')

    cmd = safe_pop(args)
    if cmd == 'install':
        cmd = safe_pop(args)
        if cmd == 'all' or cmd is None:
            install_openresty()
            install_verynginx()
        elif cmd == 'openresty':
            install_openresty()
        elif cmd == 'verynginx':
            install_verynginx()
        else:
            show_help_and_exit()
    elif cmd == 'update':
        cmd = safe_pop(args)
        if cmd == 'verynginx':
            update_verynginx()
        else:
            show_help_and_exit()
    elif cmd == 'hash-password':
        password = safe_pop(args)
        if not password:
            print('Error: password argument is required')
            sys.exit(1)
        print(hash_password(password))
        sys.exit(0)
    else:
        show_help_and_exit()

    print('*** All work finished successfully, enjoy it~')

else:
    print('install.py loaded as module')
    print('To use nginx, add it in PATH:')
    print('export PATH=' + VN_PREFIX + '/openresty/nginx/sbin:$PATH')