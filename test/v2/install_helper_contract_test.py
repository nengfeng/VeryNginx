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
 3. The socket unit used `Group=verynginx` (a process-credential directive,
    ignored in [Socket]) instead of `SocketGroup=verynginx`. The socket node
    was thus (re)created root:root on rebind and the nginx worker could not
    connect. `SocketGroup=` fixes the node's group at bind time.

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
    """Drop comment lines so prose ('do NOT add RuntimeDirectory=') does not
    trip a check meant for real systemd directives."""
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def has_directive(text, key):
    return any(l.strip().startswith(key + "=") for l in directives(text).splitlines())


def main():
    print("== install path: firewall helper systemd contract ==")
    installer = read(INSTALLER)
    tpl_svc = read(TEMPLATE_SERVICE)
    tpl_sock = read(TEMPLATE_SOCKET)
    upgrade = read(UPGRADE)

    marker = "<<SVCUNIT"
    svc_heredoc = ""
    if marker in installer:
        svc_heredoc = installer.split(marker, 1)[1].split("\nSVCUNIT", 1)[0]
    sock_marker = "<<SOCKUNIT"
    sock_heredoc = ""
    if sock_marker in installer:
        sock_heredoc = installer.split(sock_marker, 1)[1].split("\nSOCKUNIT", 1)[0]
    d_svc_install = directives(svc_heredoc)
    d_svc_tpl = directives(tpl_svc)
    d_sock_install = directives(sock_heredoc)
    d_sock_tpl = directives(tpl_sock)

    # --- Defect 1: RuntimeDirectory on the service wipes the socket file ---
    for label, text in (("installer SVCUNIT", d_svc_install),
                        ("helper/firewall-helper.service template", d_svc_tpl)):
        if has_directive(text, "RuntimeDirectory"):
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

    # --- Defect 3: socket node group via SocketGroup= (NOT Group=) ---
    for label, text in (("installer SOCKUNIT", d_sock_install),
                        ("socket template", d_sock_tpl)):
        if has_directive(text, "SocketGroup") and "SocketGroup=verynginx" in text or \
           (has_directive(text, "SocketGroup") and "SocketGroup=${vn_group}" in text):
            ok("%s sets SocketGroup= on the socket node" % label)
        else:
            ko("%s must set SocketGroup=verynginx (Group= is ignored in [Socket])" % label)
        if has_directive(text, "Group"):
            ko("%s must not use Group= in [Socket] (process cred, ignored)" % label)
        else:
            ok("%s avoids Group= in [Socket]" % label)
    # +ExecStartPre is ignored by systemd 257 — must not reappear as a directive.
    for label, text in (("installer", directives(installer)),
                        ("service template", d_svc_tpl)):
        if has_directive(text, "+ExecStartPre"):
            ko("%s must not use +ExecStartPre directive (ignored by systemd)" % label)
        else:
            ok("%s avoids +ExecStartPre directive" % label)
    # No obsolete root chgrp oneshot should remain.
    for label, text in (("installer", installer), ("service template", tpl_svc),
                        ("upgrade.sh", upgrade)):
        if "firewall-helper-permissions.service" in text:
            ko("%s must not reference the obsolete permissions oneshot" % label)
        else:
            ok("%s has no obsolete permissions oneshot" % label)

    # --- Socket unit still owns the directory + mode 0660 ---
    if "ListenStream=/run/verynginx/firewall-helper.sock" not in tpl_sock:
        ko("socket template must listen on /run/verynginx/firewall-helper.sock")
    else:
        ok("socket template listens on the expected path")
    if "SocketMode=0660" not in tpl_sock:
        ko("socket template must keep SocketMode=0660")
    else:
        ok("socket template keeps SocketMode=0660")
    if "DirectoryMode=0755" not in tpl_sock:
        ko("socket template must keep DirectoryMode=0755")
    else:
        ok("socket template keeps DirectoryMode=0755")

    # --- Upgrade path deploys both units (no oneshot) ---
    if "for _unit in firewall-helper.socket firewall-helper.service; do" not in upgrade:
        ko("upgrade.sh must deploy both firewall-helper units")
    else:
        ok("upgrade.sh deploys both firewall-helper units")

    print("")
    print("Install helper contract tests: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
