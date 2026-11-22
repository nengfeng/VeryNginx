#!/usr/bin/env python3
"""Regression tests for the Firewall Helper's systemd install contract.

Three independent defects used to produce a panel `helper_unavailable`
on a fresh install / after an upgrade (see AGENTS.md §11.5):

 1. The service unit had `RuntimeDirectory=verynginx`. On every service
    (re)start systemd wipes /run/verynginx, unlinking the socket node the
    socket unit owns -> kernel listener unreachable by path.
 2. The service unit did not set `VN_HELPER_ALLOWED_UIDS` to the nginx
    worker's uid, so the Go helper's SO_PEERCRED check rejected the worker
    even though it was in the `verynginx` group (filesystem 0660).
 3. The socket node is (re)created as root:root on rebind; `[Socket] Group=`
    is not reliably applied, and the helper service is unprivileged. A
    dedicated root oneshot (`firewall-helper-permissions.service`) pulled in
    via Wants=/After= is required to chgrp it back to verynginx. Note this
    systemd ignores `+ExecStartPre`, so that mechanism must not be used.

We do static checks on the generator/templates (running the installer would
need root and network). Run: python3 test/v2/install_helper_contract_test.py
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = 0
FAIL = 0

INSTALLER = os.path.join(ROOT, "install-lnmp.sh")
TEMPLATE_SERVICE = os.path.join(ROOT, "helper", "firewall-helper.service")
TEMPLATE_PERMS = os.path.join(ROOT, "helper", "firewall-helper-permissions.service")
TEMPLATE_SOCKET = os.path.join(ROOT, "helper", "firewall-helper.socket")
UPGRADE = os.path.join(ROOT, "tools", "upgrade.sh")


def ok(msg):
    global PASS
    PASS += 1
    print("  [PASS] %s" % msg)


def ko(msg):
    global FAIL
    FAIL += 1
    print("  [FAIL] %s" % msg)


def read(path):
    with open(path, "r") as f:
        return f.read()


def directives(text):
    """Drop comment lines so prose like 'do NOT add RuntimeDirectory=' does
    not trip a check meant for real systemd directives."""
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def after_line(text, key):
    """Return the value of an `After=` line, or '' if none."""
    for l in directives(text).splitlines():
        s = l.strip()
        if s.startswith(key + "="):
            return s.split("=", 1)[1]
    return ""


def main():
    print("== install path: firewall helper systemd contract ==")
    installer = read(INSTALLER)
    tpl_svc = read(TEMPLATE_SERVICE)
    tpl_perms = read(TEMPLATE_PERMS)
    tpl_sock = read(TEMPLATE_SOCKET)
    upgrade = read(UPGRADE)

    # The installer writes the service via a SVCUNIT heredoc; cut that out so
    # a stray directive elsewhere in the script doesn't cause a false result.
    marker = "<<SVCUNIT"
    svc_heredoc = ""
    if marker in installer:
        svc_heredoc = installer.split(marker, 1)[1].split("\nSVCUNIT", 1)[0]
    d_svc_install = directives(svc_heredoc)
    d_svc_tpl = directives(tpl_svc)

    # --- Defect 1: RuntimeDirectory on the service wipes the socket file ---
    for label, text in (("installer SVCUNIT", d_svc_install),
                        ("helper/firewall-helper.service template", d_svc_tpl)):
        if any(l.strip().startswith("RuntimeDirectory=") for l in text.splitlines()):
            ko("%s must not declare RuntimeDirectory= (wipes .sock on restart)" % label)
        else:
            ok("%s has no RuntimeDirectory=" % label)

    # --- Defect 2: peer auth allowlist ---
    if "VN_HELPER_ALLOWED_UIDS" not in d_svc_install or "vn_web_uid" not in d_svc_install:
        ko("installer must set VN_HELPER_ALLOWED_UIDS from the nginx worker uid")
    else:
        ok("installer sets VN_HELPER_ALLOWED_UIDS from the nginx worker uid")
    if "VN_HELPER_ALLOWED_UIDS" not in tpl_svc:
        ko("service template must document/allow VN_HELPER_ALLOWED_UIDS")
    else:
        ok("service template documents VN_HELPER_ALLOWED_UIDS")
    if "id -u" not in installer or "vn_web_user" not in installer:
        ko("installer must derive the worker uid via 'id -u <vn_web_user>'")
    else:
        ok("installer derives the nginx worker uid")

    # --- Defect 3: root chgrp fixup unit + Wants=/After= wiring ---
    if "firewall-helper-permissions.service" not in installer:
        ko("installer must generate firewall-helper-permissions.service")
    else:
        ok("installer generates firewall-helper-permissions.service")
    for label, text in (("installer SVCUNIT", d_svc_install),
                        ("service template", d_svc_tpl)):
        if "Wants=firewall-helper-permissions.service" not in text:
            ko("%s must Wants= the permissions fixup unit" % label)
        else:
            ok("%s Wants= the permissions fixup unit" % label)
        after = after_line(text, "After")
        if "firewall-helper-permissions.service" not in after:
            ko("%s must order After= the permissions fixup unit" % label)
        else:
            ok("%s orders After= the permissions fixup unit" % label)
    perm_block = (installer.split("<<PERMUNIT", 1)[1].split("\nPERMUNIT", 1)[0]
                  if "<<PERMUNIT" in installer else "")
    for label, text in (("installer PERMUNIT", perm_block),
                        ("permissions template", tpl_perms)):
        if "chgrp verynginx" not in text and "chgrp ${vn_group}" not in text:
            ko("%s must chgrp the .sock node to verynginx" % label)
        else:
            ok("%s chgrps the .sock node" % label)
        if "User=" in directives(text):
            ko("%s must run as root (no unprivileged User=)" % label)
        else:
            ok("%s runs as root" % label)
    # +ExecStartPre is ignored by systemd 257 — must not reappear as a directive.
    for label, text in (("installer", directives(installer)),
                        ("service template", d_svc_tpl)):
        if any(l.strip().startswith("+ExecStartPre") for l in text.splitlines()):
            ko("%s must not use +ExecStartPre directive (ignored by systemd)" % label)
        else:
            ok("%s avoids +ExecStartPre directive" % label)

    # --- Socket unit still owns the directory + mode 0660 ---
    if "ListenStream=/run/verynginx/firewall-helper.sock" not in tpl_sock:
        ko("socket template must listen on /run/verynginx/firewall-helper.sock")
    else:
        ok("socket template listens on the expected path")
    if "SocketMode=0660" not in tpl_sock:
        ko("socket template must keep SocketMode=0660")
    else:
        ok("socket template keeps SocketMode=0660")

    # --- Upgrade path deploys all three units, including the fixup ---
    if "firewall-helper-permissions.service" not in upgrade:
        ko("upgrade.sh must deploy firewall-helper-permissions.service")
    else:
        ok("upgrade.sh deploys firewall-helper-permissions.service")

    print("")
    print("Install helper contract tests: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
