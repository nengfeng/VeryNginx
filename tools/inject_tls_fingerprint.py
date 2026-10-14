#!/usr/bin/env python3
"""
Inject the VeryNginx TLS-fingerprint hook (ssl_client_hello_by_lua_block) into
every VeryNginx-managed SSL server block.

Why a tool and not a sed one-liner: the directive may only appear in a context
that has SSL configured, and lua-nginx-module enforces that PER SERVER — an
http-level block fails nginx -t with "no ssl configured for the server" the
moment any plain-HTTP server exists in the same http block (LNMP always ships
one, the :80 default vhost). It is also not additive, so it must appear
exactly once per server.

Injection target = server blocks that BOTH:
  * carry the VeryNginx handlers (access_by_lua_file .../on_access.lua), i.e.
    the blocks the WAF actually runs in, and
  * have an ssl_certificate, i.e. real TLS handshakes occur there.

Idempotent: a server that already includes the snippet is left alone.
Usage:
  inject_tls_fingerprint.py --nginx-conf /usr/local/nginx/conf/nginx.conf
      [--include <snippet path>] [--dry-run] [--backup]

Include depth: the main conf plus the files it includes with a literal glob or
path at one level (same limitation as install-lnmp.sh's directive_file).
"""

import argparse
import glob
import os
import re
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SNIPPET = os.path.normpath(os.path.join(HERE, "..", "verynginx", "nginx_conf", "tls-fingerprint.conf"))

HANDLER_RE = re.compile(r"\b(?:rewrite|access|log)_by_lua_file\s+[^;]*on_(?:rewrite|access|log)\.lua\s*;")
SSL_RE = re.compile(r"\bssl_certificate\s+[^;]+;")
HAS_HOOK_RE = re.compile(r"tls-fingerprint\.conf")
INCLUDE_RE = re.compile(r"^[ \t]*include\s+([^;]+);", re.M)


def mask_comments_strings(t):
    """Blank out comments and quoted strings so brace matching is reliable."""
    out = list(t)
    i, n = 0, len(t)
    while i < n:
        c = t[i]
        if c == "#":
            while i < n and t[i] != "\n":
                out[i] = " "
                i += 1
        elif c in "\"'":
            q = c
            while i < n and t[i] != "\n":
                out[i] = " "
                if t[i] == "\\" and i + 1 < n:
                    out[i + 1] = " "
                    i += 2
                    continue
                if t[i] == q:
                    i += 1
                    break
                i += 1
        else:
            i += 1
    return "".join(out)


def match_brace(t, open_idx):
    depth = 0
    for i in range(open_idx, len(t)):
        if t[i] == "{":
            depth += 1
        elif t[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def server_blocks(masked):
    spans = []
    for m in re.finditer(r"\bserver\b[ \t]*\{", masked):
        ob = m.end() - 1
        cb = match_brace(masked, ob)
        if cb != -1:
            spans.append((m.start(), ob, cb))
    return spans


def stream_spans(masked):
    spans = []
    for m in re.finditer(r"\bstream\b[ \t]*\{", masked):
        ob = m.end() - 1
        cb = match_brace(masked, ob)
        if cb != -1:
            spans.append((m.start(), ob, cb))
    return spans


def expand_includes(conf_path, masked):
    """Files pulled in by literal/one-level-glob includes (nginx.conf only)."""
    files = []
    base = os.path.dirname(conf_path)
    for m in INCLUDE_RE.finditer(masked):
        pat = m.group(1).strip().strip("'\"")
        if any(ch in pat for ch in "*?["):
            files.extend(sorted(glob.glob(os.path.join(base, pat))))
        elif "/" in pat:
            p = pat if os.path.isabs(pat) else os.path.join(base, pat)
            if os.path.isfile(p):
                files.append(p)
    return files


def check_file(path, snippet_path):
    """只审计：该文件里每个 SSL server 是否都有钩子。返回缺失数量。"""
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:
        print("  [ERROR ] %s %s" % (path, e))
        return 0
    masked = mask_comments_strings(text)
    streams = stream_spans(masked)
    missing = 0
    total = 0
    for start, ob, cb in server_blocks(masked):
        inner = text[ob + 1:cb]
        if any(a <= start <= c for a, _b, c in streams):
            continue
        if not SSL_RE.search(inner):
            continue  # 非 TLS server：放该指令会让 nginx -t 失败
        total += 1
        name = re.search(r"server_name\s+([^;]+);", inner)
        label = name.group(1).strip() if name else "(no server_name)"
        if HAS_HOOK_RE.search(inner):
            print("  [OK     ] %s  %s" % (os.path.basename(path), label))
        else:
            missing += 1
            print("  [MISSING] %s  %s" % (os.path.basename(path), label))
    if total == 0 and not missing:
        print("  [NONE   ] %s  (no SSL server block)" % os.path.basename(path))
    return missing


def inject_file(path, snippet_path, dry_run):
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:
        return [{"file": path, "action": "ERROR", "detail": str(e)}]
    masked = mask_comments_strings(text)
    streams = stream_spans(masked)
    results = []

    edits = []  # (insert_pos, server_start)
    for start, ob, cb in server_blocks(masked):
        inner = text[ob + 1:cb]
        if any(a <= start <= c for a, _b, c in streams):
            continue  # stream{} server — L4 proxying, not an HTTP vhost
        if not SSL_RE.search(inner):
            continue  # no TLS here: the directive would fail nginx -t
        # NOTE: do NOT restrict this to VeryNginx-managed servers (those with
        # on_access.lua). lua-nginx-module installs the SSL client-hello
        # callback per listen socket: once ANY server block on :443 defines
        # ssl_client_hello_by_lua*, every OTHER server without it aborts the
        # handshake with "no ssl_client_hello_by_lua* defined in server X"
        # (NGX_LOG_ALERT) — which surfaces to users as Cloudflare 525. The
        # hook is harmless on non-WAF servers (it only computes a fingerprint
        # and stores it on ngx.ctx; nothing reads it there), so it must go
        # into EVERY SSL server block, not just the managed ones.
        if HAS_HOOK_RE.search(inner):
            results.append({"file": path, "action": "SKIP", "detail": "hook already present"})
            continue
        handlers = list(HANDLER_RE.finditer(inner))
        pos = ob + 1 + handlers[-1].end() if handlers else ob + 1 + SSL_RE.search(inner).end()
        edits.append((pos, start))

    if not edits:
        if not results:
            results.append({"file": path, "action": "NONE", "detail": "no matching server block"})
        return results

    # apply from the end so earlier offsets stay valid
    for pos, _start in sorted(edits, reverse=True):
        line = "\n    include %s;" % snippet_path
        text = text[:pos] + line + text[pos:]

    if not dry_run:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    results.append({"file": path, "action": "INJECTED" if not dry_run else "WOULD-INJECT",
                    "detail": "%d server block(s)" % len(edits)})
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nginx-conf", default="/usr/local/nginx/conf/nginx.conf")
    ap.add_argument("--include", dest="snippet", default=DEFAULT_SNIPPET)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--backup", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="只审计不改写：列出缺少钩子的 SSL server，有缺失则退出码非 0。"
                         "新增域名/站点后跑一次，确认 TLS 不会被 client-hello 回调中止。")
    args = ap.parse_args()

    if not os.path.isfile(args.snippet):
        print("snippet not found: %s" % args.snippet, file=sys.stderr)
        return 2

    conf = args.nginx_conf
    targets = [conf]
    masked = mask_comments_strings(open(conf, encoding="utf-8").read())
    targets.extend(expand_includes(conf, masked))

    if args.backup and not args.dry_run:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        for p in targets:
            shutil.copy2(p, "%s.pre-ja4.%s" % (p, stamp))
        print("backup: *.pre-ja4.%s" % stamp)

    if args.check:
        missing = 0
        for p in dict.fromkeys(targets):
            missing += check_file(p, args.snippet)
        if missing:
            print("MISSING: %d 个 SSL server 缺少 %s —— 它们的 TLS 握手会被中止"
                  "（用户侧表现为 Cloudflare 525）。修复："
                  "python3 %s --nginx-conf %s --include %s --backup"
                  % (missing, os.path.basename(args.snippet),
                     os.path.abspath(__file__), conf, args.snippet))
            return 1
        print("OK: 所有 SSL server 均已包含握手钩子")
        return 0

    total = 0
    for p in dict.fromkeys(targets):
        for r in inject_file(p, args.snippet, args.dry_run):
            total += 1
            print("  [%-12s] %s %s" % (r["action"], r["file"], r["detail"]))
    print("done: %d file action(s)" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())