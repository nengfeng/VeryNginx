#!/usr/bin/env python3
"""Regression tests for the installer's server-block patcher.

Field bug: replace_server_block() picked ONE server{} from nginx.conf and
never touched included vhosts, so a filed domain served from a vhost include
got no VeryNginx handlers / dashboard locations -> panel unreachable by domain.

These tests extract the embedded Python script from install-lnmp.sh, run it
against a synthetic nginx.conf with HTTP servers + vhost includes + a stream
server, and assert every HTTP server is patched while stream stays untouched.
Run: python3 test/v2/install_vhost_patch_test.py
"""

import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INSTALLER = os.path.join(ROOT, "install-lnmp.sh")

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print("  [PASS] %s" % msg)


def ko(msg):
    global FAIL
    FAIL += 1
    print("  [FAIL] %s" % msg)


def extract_patcher():
    src = open(INSTALLER).read()
    i = src.index("replace_server_block() {")
    j = src.index("<< 'PYEOF'", i) + len("<< 'PYEOF'")
    k = src.index("\nPYEOF", j)
    return src[j:k]


def main():
    print("== installer: all HTTP server blocks patched ==")
    script = extract_patcher()
    if "collect_files" not in script or "make_vn_new" not in script:
        ko("patcher source missing collect_files/make_vn_new helpers")
        print("install vhost patch tests: %d passed, %d failed" % (PASS, FAIL))
        return 1

    tmp = tempfile.mkdtemp(prefix="vn-patch-")
    try:
        conf_dir = os.path.join(tmp, "conf")
        vhost_dir = os.path.join(conf_dir, "vhost")
        os.makedirs(vhost_dir)
        nginx_conf = os.path.join(conf_dir, "nginx.conf")
        vn_dir = os.path.join(tmp, "verynginx")

        open(nginx_conf, "w").write("""events { worker_connections 1; }
http {
    include vhost/*.conf;
    server {
        listen 80;
        server_name default;
    }
}
stream {
    server { listen 9000; }
}
""")
        open(os.path.join(vhost_dir, "a.conf"), "w").write("""server {
    listen 80;
    server_name a.example.com;
}
""")
        open(os.path.join(vhost_dir, "b.conf"), "w").write("""server {
    listen 443 ssl;
    server_name b.example.com;
}
""")

        py = os.path.join(tmp, "patch.py")
        open(py, "w").write(script)
        r = subprocess.run([sys.executable, py, nginx_conf, vn_dir],
                           capture_output=True, text=True)
        if r.returncode != 0:
            ko("patcher exited non-zero: %s %s" % (r.stdout, r.stderr))
            print("install vhost patch tests: %d passed, %d failed" % (PASS, FAIL))
            return 1
        if not r.stdout.startswith("OK "):
            ko("expected OK result, got: %s" % r.stdout.strip())
            print("install vhost patch tests: %d passed, %d failed" % (PASS, FAIL))
            return 1
        ok("patcher reports OK with counts: %s" % r.stdout.strip())

        main_txt = open(nginx_conf).read()
        a_txt = open(os.path.join(vhost_dir, "a.conf")).read()
        b_txt = open(os.path.join(vhost_dir, "b.conf")).read()

        for label, txt in (("nginx.conf server", main_txt),
                           ("vhost a.conf", a_txt), ("vhost b.conf", b_txt)):
            if (vn_dir + "/on_rewrite.lua" in txt and
                    "location /verynginx/" in txt and
                    "location /verynginx/static/" in txt):
                ok("%s got handlers + both locations" % label)
            else:
                ko("%s missing handlers/locations" % label)

        # stream{} server must NOT be patched
        stream_part = main_txt.split("stream {", 1)[1]
        if vn_dir + "/on_rewrite.lua" not in stream_part:
            ok("stream{} server left untouched")
        else:
            ko("stream{} server was incorrectly patched")

        # idempotency: second run must report ALREADY_PRESENT, no duplicates
        r2 = subprocess.run([sys.executable, py, nginx_conf, vn_dir],
                            capture_output=True, text=True)
        if r2.stdout.strip() == "ALREADY_PRESENT":
            ok("second run is idempotent (ALREADY_PRESENT)")
        else:
            ko("second run output: %s" % r2.stdout.strip())
        a2 = open(os.path.join(vhost_dir, "a.conf")).read()
        if a2.count(vn_dir + "/on_rewrite.lua") == 1:
            ok("no duplicate handlers after re-run")
        else:
            ko("duplicate handlers after re-run (%d)" % a2.count(vn_dir + "/on_rewrite.lua"))

        # backup created for modified files
        if glob.glob(nginx_conf + ".bak.*"):
            ok("timestamped backup created")
        else:
            ko("no backup created for modified file")

        # NO_SERVER case
        empty = os.path.join(tmp, "empty.conf")
        open(empty, "w").write("events {}\nhttp { include mime.types; }\n")
        r3 = subprocess.run([sys.executable, py, empty, vn_dir],
                            capture_output=True, text=True)
        if r3.stdout.strip() == "NO_SERVER":
            ok("no-server config reports NO_SERVER")
        else:
            ko("no-server output: %s" % r3.stdout.strip())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("")
    print("install vhost patch tests: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
