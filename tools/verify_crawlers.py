#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch-verify crawler IPs seen in the access logs, outside the request path.

Why this exists alongside the online check (core/crawler_verify.lua)
--------------------------------------------------------------------
The online check has to be non-blocking, non-blocking DNS through cosockets
included, and it runs one timer per previously-unseen address. That is the
right shape for correctness but it means every new crawler IP pays a cold
forward lookup on its first request.

This tool does the same verification with ordinary blocking DNS, where a slow
answer costs nothing but wall-clock in a cron job, and writes the confirmed
addresses into ip_reputation.crawler_ip_verified. Verified addresses then hit
on the cheap path in nginx: a shared-dict lookup, no DNS at all.

Splitting the work this way also means the resolver question is decided here,
once, by measurement, instead of on the request path.

Resolvers
---------
The list is configurable and is PROBED, not assumed. This matters because
reachability is a property of where the server is, not of the resolver:
8.8.8.8 and 1.1.1.1 answer in ~20ms from the current host (which is outside
China) and are typically unreachable from a deployment inside China. Whatever
answers, answers, and if none do the tool says so and writes nothing.

Usage
-----
    python3 tools/verify_crawlers.py --dry-run
    python3 tools/verify_crawlers.py --apply
    python3 tools/verify_crawlers.py --apply --resolvers 223.5.5.5,119.29.29.29

Logs are read with the nginx combined format; the User-Agent is the last
quoted field. Only addresses whose User-Agent matches a configured vendor's
pattern are considered, so the tool never verifies the whole internet.
"""

import argparse
import ipaddress
import json
import os
import random
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

DEFAULT_CONFIG = "/opt/verynginx/configs/config.json"
DEFAULT_LOGS = "/data/wwwlogs"
# Google's list is /27s, Bing /22s; DuckDuckBot is hundreds of /32s. Either
# way a DNS lookup per candidate, so cap the batch rather than let a busy log
# turn into tens of thousands of queries.
DEFAULT_MAX_CANDIDATES = 500
UA_RE = re.compile(r'"(?:[^"\\]|\\.)*"\s*$')


def sh(cmd, timeout=10):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def dig(args, resolver, timeout=5):
    """Return (dns_status, values).

    The status is the whole point. `+short` alone renders "the resolver
    answered: this name has no PTR record" and "the resolver never answered"
    as the same empty output, and those two must never collapse: the first is
    evidence the address is not the vendor's, the second is our own DNS being
    unwell. Condemning a crawler because our resolver timed out is exactly
    the failure this whole design is built to avoid.

    Returns ("NOERROR"|"NXDOMAIN"|"SERVFAIL"|"REFUSED"|"TIMEOUT", values)
    """
    code, out, _ = sh(["dig", "+time=%d" % timeout, "+tries=1", "+comments", "+answer"]
                      + args + ["@" + resolver], timeout=timeout + 3)
    if code != 0:
        return "TIMEOUT", []
    status = None
    for line in out.splitlines():
        if line.startswith(";; ->>HEADER"):
            if "status:" in line:
                status = line.split("status:")[1].split(",")[0].strip()
            break
    if status is None:
        return "TIMEOUT", []
    vals = []
    for line in out.splitlines():
        if not line or line.startswith(";"):
            continue
        # Answer lines are "name TTL IN TYPE RDATA", so the class marker sits
        # at a shifting offset once the RDATA itself contains spaces (TXT,
        # SRV). Locate the class instead of counting from the end: a fixed
        # parts[-2] == "IN" test silently yields zero records, which then
        # reads as "this address has no PTR" and condemns real crawlers.
        parts = line.split()
        if "IN" not in parts:
            continue
        idx = parts.index("IN")
        if idx + 2 >= len(parts):
            continue
        vals.append(" ".join(parts[idx + 2:]).rstrip("."))
    if status not in ("NOERROR", "NXDOMAIN"):
        return status, []
    return status, vals


# DNS statuses that mean "the resolver answered". Only these may produce a
# fake verdict; anything else is our infrastructure, not the crawler.
ANSWERED = ("NOERROR", "NXDOMAIN")


def resolver_answers(resolver, probe_name="www.baidu.com", tries=2):
    for _ in range(tries):
        status, vals = dig(["A", probe_name], resolver)
        if status in ANSWERED and vals:
            return True
    return False


def ptr(ip, resolver):
    """@return "ok", name | "absent" (answered: no PTR) | "noanswer" (DNS unwell)"""
    status, vals = dig(["-x", ip], resolver)
    if status not in ANSWERED:
        return "noanswer", None
    if not vals:
        return "absent", None
    return "ok", vals[0]


def forward_confirms(name, ip, resolver):
    status, vals = dig(["A", name], resolver)
    if status not in ANSWERED:
        return None            # unknown: cannot confirm or deny
    return any(v == ip for v in vals)


def domain_ok(name, domains):
    name = name.lower().rstrip(".")
    for d in domains:
        d = d.lower().rstrip(".")
        if name == d or name.endswith("." + d):
            return True
    return False


def ua_of(line):
    # The trailing newline matters: UA_RE ends in \s*$, so a newline is
    # captured INSIDE the match. Slicing group(0)[1:-1] before stripping it
    # would cut the closing quote instead of the newline and break the JSON
    # unescape below — which fails silently into a "no candidates" run that
    # looks exactly like "no crawlers today".
    line = line.rstrip("\r\n")
    m = UA_RE.search(line)
    if not m:
        return None
    quoted = m.group(0).strip()
    if len(quoted) < 2 or not quoted.startswith('"') or not quoted.endswith('"'):
        return None
    try:
        return json.loads(quoted)
    except Exception:
        # Malformed escaping in one log line is not worth aborting the batch.
        return None


def collect_candidates(log_paths, vendors, max_candidates, since_hours):
    """Addresses that CLAIM one of the vendors, newest first."""
    cutoff = time.time() - since_hours * 3600
    found = {}
    scanned = 0
    for path in log_paths:
        try:
            st = os.stat(path)
        except OSError:
            continue
        if st.st_mtime < cutoff:
            continue
        try:
            # Tail rather than read whole files: these run to hundreds of MB.
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 4 * 1024 * 1024))
                if size > 4 * 1024 * 1024:
                    f.readline()          # drop a partial first line
                for raw in f:
                    scanned += 1
                    line = raw.decode("utf-8", "replace")
                    ua = ua_of(line)
                    if not ua:
                        continue
                    for key, v in vendors.items():
                        if re.search(v.get("ua_pattern", "(?!)"), ua, re.I):
                            ip = line.split(" ", 1)[0]
                            try:
                                addr = ipaddress.ip_address(ip)
                            except ValueError:
                                continue
                            if addr.version != 4:
                                continue     # crawler_ip_verified is IPv4-only
                            found.setdefault(ip, key)
                            break
                    if len(found) >= max_candidates:
                        return found, scanned
        except OSError as exc:
            print("  [WARN] 读取 %s 失败: %s" % (path, exc), file=sys.stderr)
    return found, scanned


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--logs", default=DEFAULT_LOGS)
    ap.add_argument("--resolvers", help="comma-separated override; default from config")
    ap.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES)
    ap.add_argument("--since-hours", type=int, default=24)
    ap.add_argument("--min-agreement", type=int, help="default from config")
    ap.add_argument("--apply", action="store_true", help="write verified addresses to the config")
    ap.add_argument("--prune", action="store_true",
                    help="drop verified entries whose PTR no longer resolves to them")
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as f:
        conf = json.load(f)
    ir = conf.setdefault("ip_reputation", {})
    cv = ir.get("crawler_verify") or {}
    vendors = {k: v for k, v in (cv.get("vendors") or {}).items()
               if v.get("enabled", True)}
    if not vendors:
        print("配置里没有启用的 crawler_verify.vendors，无需处理。", file=sys.stderr)
        return 0

    resolvers = ([r.strip() for r in args.resolvers.split(",")] if args.resolvers
                 else (cv.get("resolvers") or ["8.8.8.8", "1.1.1.1", "223.5.5.5"]))
    need = args.min_agreement or int(cv.get("min_agreement") or 2)
    require_forward = True

    print("校验厂商: %s" % ", ".join(sorted(vendors)), file=sys.stderr)
    log_paths = []
    if os.path.isdir(args.logs):
        for name in sorted(os.listdir(args.logs)):
            if name.endswith("_nginx.log"):
                log_paths.append(os.path.join(args.logs, name))
    elif os.path.isfile(args.logs):
        log_paths.append(args.logs)

    candidates, scanned = collect_candidates(log_paths, vendors, args.max_candidates,
                                             args.since_hours)
    print("扫描 %d 行日志，得到 %d 个声称是厂商爬虫的地址（上限 %d）"
          % (scanned, len(candidates), args.max_candidates), file=sys.stderr)
    if not candidates:
        print("没有候选地址，无需写入。", file=sys.stderr)
        return 0

    # Order candidates most-recent-first-ish by shuffling: DNS answers are
    # cached per resolver, so any order works, but a stable order makes a
    # truncated batch predictable.
    ips = list(candidates)
    random.Random(0).shuffle(ips)

    print("探测解析器可达性 ...", file=sys.stderr)
    live = [r for r in resolvers if resolver_answers(r)]
    dead = [r for r in resolvers if r not in live]
    for r in live:
        print("  [ OK ] %s" % r, file=sys.stderr)
    for r in dead:
        print("  [DEAD] %s 无应答（这台机器上不可达）" % r, file=sys.stderr)
    if not live:
        print("\n所有配置的解析器都无应答。没有写入任何内容 —— "
              "把自己的 DNS 故障当成\"冒充\"去封禁，会把真实爬虫全部挡在门外。",
              file=sys.stderr)
        return 2
    if need > len(live):
        print("  min_agreement=%d 但只有 %d 个解析器可用，按可用数执行" % (need, len(live)),
              file=sys.stderr)
        need = len(live)

    verified, fake, unknown = [], [], []
    reasons = {}
    for i, ip in enumerate(ips, 1):
        vendor = vendors[candidates[ip]]
        v_ok = v_fake = v_unknown = 0
        detail = []
        for r in live:
            state, name = ptr(ip, r)
            if state == "noanswer":
                v_unknown += 1
                detail.append("%s: 未回答" % r)
                continue
            if state == "absent":
                # DNS answered and there is no PTR at all. A real vendor
                # crawler always has one, so this counts as evidence of an
                # impersonator — which is why it is NOT lumped in with the
                # resolvers that simply stayed quiet.
                v_fake += 1
                detail.append("%s: 明确无 PTR 记录" % r)
                continue
            if not domain_ok(name, vendor.get("domains") or []):
                v_fake += 1
                detail.append("%s: PTR=%s 不在厂商域名内" % (r, name))
                continue
            if require_forward:
                fwd = forward_confirms(name, ip, r)
                if fwd is None:
                    v_unknown += 1
                    detail.append("%s: 正向查询未回答" % r)
                    continue
                if not fwd:
                    v_fake += 1
                    detail.append("%s: PTR=%s 正向未回指原 IP" % (r, name))
                    continue
            v_ok += 1
        if v_ok >= need:
            verified.append(ip)
        elif v_fake >= need:
            fake.append(ip)
            reasons[ip] = "; ".join(detail[:2])
        else:
            unknown.append(ip)
            reasons[ip] = ("; ".join(detail[:2])
                           or "解析器回答不一致 (ok=%d fake=%d unknown=%d)" % (v_ok, v_fake, v_unknown))
        if i % 25 == 0:
            print("  ... %d/%d" % (i, len(ips)), file=sys.stderr)

    print("\n结果: 验证通过 %d / 确认冒充 %d / 不确定 %d"
          % (len(verified), len(fake), len(unknown)), file=sys.stderr)
    if unknown[:5]:
        print("不确定的前 5 个（不写入任何一侧）:", file=sys.stderr)
        for ip in unknown[:5]:
            print("   %-16s %s" % (ip, reasons.get(ip, "")), file=sys.stderr)

    if not args.apply:
        print(json.dumps({"verified": sorted(verified), "fake": sorted(fake),
                          "unknown": sorted(unknown),
                          "resolvers_used": live, "resolvers_dead": dead},
                         ensure_ascii=False, indent=2))
        return 0

    existing = set(ir.get("crawler_ip_verified") or [])
    before = len(existing)
    if args.prune:
        keep = [x for x in sorted(existing) if x in set(verified)]
        print("  剪枝: %d -> %d 条旧记录" % (before, len(keep)), file=sys.stderr)
    else:
        keep = sorted(existing)
    merged = sorted(set(keep) | set(verified))
    ir["crawler_ip_verified"] = merged
    ir["crawler_ip_verified_at"] = datetime.now(timezone.utc).isoformat()
    ir["crawler_ip_verified_sources"] = [{
        "resolvers_used": live, "resolvers_dead": dead,
        "min_agreement": need, "candidates": len(ips),
    }]

    tmp = args.config + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(conf, f, ensure_ascii=False, indent=4)
        f.write("\n")
    os.replace(tmp, args.config)
    print("\n写入 %s: crawler_ip_verified %d -> %d 条"
          % (args.config, before, len(merged)), file=sys.stderr)
    print("Reload VeryNginx for the change to take effect.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
