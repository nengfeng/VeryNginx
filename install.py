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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

openresty_pkg_url = 'https://openresty.org/download/openresty-1.31.1.1.tar.gz'
openresty_pkg = 'openresty-1.31.1.1.tar.gz'

work_path = os.getcwd()

# ---------------------------------------------------------------------------
# Install OpenResty
# ---------------------------------------------------------------------------

def install_openresty():
    if os.path.exists('/opt/VeryNginx/VeryNginx') == True:
        print("Seems that a old version of VeryNginx was installed in /opt/verynginx/...")
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

    print('### release the package ...')
    exec_sys_cmd('tar -xzf ' + openresty_pkg)

    print('### configure openresty ...')
    os.chdir(openresty_pkg.replace('.tar.gz',''))
    exec_sys_cmd(
        './configure --prefix=/opt/verynginx/openresty '
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

    if os.path.exists('/opt/verynginx/') == False:
        exec_sys_cmd('mkdir -p /opt/verynginx')

    # Copy v2 source code (configs/config.json is gitignored, not overwritten)
    exec_sys_cmd('cp -r -f ./verynginx /opt/verynginx')

    # Bootstrap config: create config.json from template if not exists
    config_json = '/opt/verynginx/verynginx/configs/config.json'
    config_default = '/opt/verynginx/verynginx/configs/config.default.json'
    if not os.path.exists(config_json):
        if os.path.exists(config_default):
            print('### bootstrap config: copy config.default.json -> config.json')
            shutil.copyfile(config_default, config_json)
            print('### IMPORTANT: edit config.json and set admin password_hash before use')
        else:
            print('### WARNING: no config.default.json found, will use built-in defaults')

    # Ensure backups directory exists
    backups_dir = '/opt/verynginx/verynginx/configs/backups'
    if not os.path.exists(backups_dir):
        os.makedirs(backups_dir)

    # Copy nginx.conf to openresty (if openresty is installed and has default config)
    openresty_conf = '/opt/verynginx/openresty/nginx/conf/nginx.conf'
    openresty_conf_default = '/opt/verynginx/openresty/nginx/conf/nginx.conf.default'
    if os.path.exists('/opt/verynginx/openresty') == True:
        if os.path.exists(openresty_conf_default) and filecmp.cmp(openresty_conf, openresty_conf_default, False) == True:
            print('### copy nginx config file to openresty')
            exec_sys_cmd('cp -f ./nginx.conf /opt/verynginx/openresty/nginx/conf/')
        elif not os.path.exists(openresty_conf_default):
            print('### copy nginx config file to openresty (first install)')
            exec_sys_cmd('cp -f ./nginx.conf /opt/verynginx/openresty/nginx/conf/')
    else:
        print('### openresty not found, so not copying nginx.conf')

    # Set permissions for config storage
    exec_sys_cmd('chmod -R 755 /opt/verynginx/verynginx/configs')

    print('### create nginx user/group if not exist')
    exec_sys_cmd('id -u nginx > /dev/null 2>&1 || useradd -r -s /sbin/nologin nginx', accept_failed=True)

def update_verynginx():
    print('### WARNING: update will keep existing config.json')
    print('### Backup your config:\n    cp /opt/verynginx/verynginx/configs/config.json ~/')
    ans = common_input('Continue? (y/n): ')
    if ans != 'y':
        print('Update cancelled.')
        return

    # Backup config
    config_json = '/opt/verynginx/verynginx/configs/config.json'
    config_backup = '/opt/verynginx/verynginx/configs/config.json.update_backup'
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

def hash_password(password, iterations=12000):
    """Generate a PBKDF2-HMAC-SHA256 hash compatible with VeryNginx v2.

    Same algorithm as core/password_hash.lua.
    Format: p1$iterations$salt_b64$hash_b64
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
    help_doc = '''usage: install.py <cmd> <args> ...

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
    opts, args = getopt.getopt(sys.argv[1:], '', [])

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
    print('export PATH=/opt/verynginx/openresty/nginx/sbin:$PATH')