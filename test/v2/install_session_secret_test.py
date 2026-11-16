#!/usr/bin/env python3
"""
Install-path contract: an installed panel must be able to log in.

The shipped config template deliberately carries NO security.session_secret:
the key is a per-installation HMAC secret, so a template that had one would
ship the SAME secret to every install. Both install paths must therefore
generate it at install time.

install-lnmp.sh did (secrets.token_hex(32)); install.py did not. The panel
came up with the schema default ("") and api/auth.lua's fail-closed guard
(a secret shorter than 16 chars) rejected every login — the panel was
unusable until someone edited config.json by hand. install.py now injects
the key.

This test exercises install.py's injection logic against the REAL shipped
template, without running the installer (which would need root and network).

Run: python3 test/v2/install_session_secret_test.py
"""

import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEMPLATE = os.path.join(ROOT, "verynginx", "configs", "config.default.json")

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


def load_installer():
    """Import install.py as a module so the test drives the SHIPPED code.

    install.py runs its installer only under `if __name__ == '__main__'`, so
    importing it is side-effect free — but importing it also prints the
    "loaded as module" banner, which is harmless here.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "vn_install", os.path.join(ROOT, "install.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_installer_source_has_the_injection():
    """install.py must actually contain the injection."""
    with open(os.path.join(ROOT, "install.py"), "r") as f:
        src = f.read()
    if "session_secret" in src and "os.urandom" in src:
        ok("install.py contains the session_secret injection")
    else:
        ko("install.py does NOT inject session_secret")


def test_template_has_no_secret():
    """The template must NOT carry a secret (it would ship to every install)."""
    with open(TEMPLATE, "r") as f:
        cfg = json.load(f)
    sec = cfg.get("security") or {}
    if not sec.get("session_secret"):
        ok("shipped template carries no session_secret")
    else:
        ko("shipped template LEAKS a session_secret to every install")


def test_fresh_install_gets_a_usable_secret(installer):
    """A fresh install must end up with a secret auth would accept."""
    tmp = tempfile.mkdtemp()
    try:
        cfg_path = os.path.join(tmp, "config.json")
        shutil.copyfile(TEMPLATE, cfg_path)
        # The installer copies the template verbatim, so that is the state
        # the injection has to fix.
        with open(cfg_path, "r") as f:
            before = json.load(f)
        if not (before.get("security") or {}).get("session_secret"):
            ok("fresh copy of the template has no session_secret (the bug)")
        else:
            ko("unexpected: the copied template already has a secret")

        result = installer.ensure_session_secret(cfg_path)
        if result == "INJECTED":
            ok("injection ran")
        else:
            ko("injection did not run: %s" % result)

        with open(cfg_path, "r") as f:
            cfg = json.load(f)   # must still be valid JSON
        secret = (cfg.get("security") or {}).get("session_secret")
        if secret and len(secret) >= 16:
            ok("secret is present and long enough for auth.lua (%d chars)" % len(secret))
        else:
            ko("secret missing or too short: %r" % secret)

        # The rest of the config must survive untouched.
        if cfg.get("base_uri") == "/verynginx" and cfg.get("admin"):
            ok("the rest of the config survived the injection")
        else:
            ko("injection damaged the config")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_existing_secret_is_never_overwritten(installer):
    """A re-install must not invalidate live sessions."""
    tmp = tempfile.mkdtemp()
    try:
        cfg_path = os.path.join(tmp, "config.json")
        shutil.copyfile(TEMPLATE, cfg_path)
        installer.ensure_session_secret(cfg_path)
        with open(cfg_path, "r") as f:
            first = json.load(f)["security"]["session_secret"]

        result = installer.ensure_session_secret(cfg_path)
        with open(cfg_path, "r") as f:
            second = json.load(f)["security"]["session_secret"]
        if result == "SKIP" and first == second:
            ok("an existing secret is left alone")
        else:
            ko("existing secret was overwritten (result=%s)" % result)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_missing_security_section(installer):
    """A config without a "security" object must still get a secret."""
    tmp = tempfile.mkdtemp()
    try:
        cfg_path = os.path.join(tmp, "config.json")
        with open(cfg_path, "w") as f:
            f.write('{\n  "version": "2.0",\n  "base_uri": "/verynginx"\n}\n')
        result = installer.ensure_session_secret(cfg_path)
        with open(cfg_path, "r") as f:
            cfg = json.load(f)
        secret = (cfg.get("security") or {}).get("session_secret")
        if result == "INJECTED" and secret and len(secret) >= 16:
            ok("a config without a security section still gets a secret")
        else:
            ko("no secret injected (result=%s, secret=%r)" % (result, secret))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_missing_config_file(installer):
    """A missing config.json is reported, not silently ignored."""
    tmp = tempfile.mkdtemp()
    try:
        result = installer.ensure_session_secret(os.path.join(tmp, "nope.json"))
        if result == "MISSING":
            ok("a missing config.json is reported")
        else:
            ko("unexpected result for a missing file: %s" % result)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_upgrade_script_backfills_the_secret():
    """upgrade.sh must backfill the secret too.

    upgrade.sh does NOT overwrite configs/config.json (it is user data), so a
    panel installed by the old install.py stays without a secret after an
    upgrade — and stays unloginable. The upgrade path needs the same fix.
    """
    with open(os.path.join(ROOT, "tools", "upgrade.sh"), "r") as f:
        script = f.read()
    if "session_secret" in script and "os.urandom" in script:
        ok("upgrade.sh contains the session_secret backfill")
    else:
        ko("upgrade.sh does NOT backfill session_secret")


def test_upgrade_backfill_logic():
    """Run the backfill snippet upgrade.sh ships, on a real config."""
    import re as _re
    with open(os.path.join(ROOT, "tools", "upgrade.sh"), "r") as f:
        script = f.read()
    # Extract the embedded python heredoc from the upgrade script.
    m = _re.search(r"<<'PYEOF'[^\n]*\n(.*?)\nPYEOF\b", script, _re.S)
    if not m:
        ko("could not extract the backfill snippet from upgrade.sh")
        return
    snippet = m.group(1)

    tmp = tempfile.mkdtemp()
    try:
        cfg_path = os.path.join(tmp, "config.json")
        shutil.copyfile(TEMPLATE, cfg_path)
        script_path = os.path.join(tmp, "snippet.py")
        with open(script_path, "w") as f:
            f.write(snippet)
        import subprocess
        r = subprocess.run([sys.executable, script_path, cfg_path],
                           capture_output=True, text=True, timeout=20)
        out = (r.stdout or "").strip()
        if out == "GENERATED":
            ok("upgrade.sh backfill generated a secret")
        else:
            ko("upgrade.sh backfill said %r" % out)

        with open(cfg_path, "r") as f:
            cfg = json.load(f)
        secret = (cfg.get("security") or {}).get("session_secret")
        if secret and len(secret) >= 16:
            ok("the backfilled secret is usable by auth.lua (%d chars)" % len(secret))
        else:
            ko("the backfilled secret is missing or too short: %r" % secret)

        # A second run must not overwrite it.
        r2 = subprocess.run([sys.executable, script_path, cfg_path],
                            capture_output=True, text=True, timeout=20)
        with open(cfg_path, "r") as f:
            again = json.load(f)["security"]["session_secret"]
        if (r2.stdout or "").strip() == "EXISTS" and again == secret:
            ok("a re-run leaves the existing secret alone")
        else:
            ko("re-run did not preserve the secret")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    print("== install path: security.session_secret ==")
    installer = load_installer()
    test_installer_source_has_the_injection()
    test_template_has_no_secret()
    test_fresh_install_gets_a_usable_secret(installer)
    test_existing_secret_is_never_overwritten(installer)
    test_missing_security_section(installer)
    test_missing_config_file(installer)
    test_upgrade_script_backfills_the_secret()
    test_upgrade_backfill_logic()

    print("")
    print("Install path tests: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
