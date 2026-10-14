#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fetch verified search-engine / AI-crawler IP ranges into VeryNginx config.

Why this is a script and not a baked-in list
--------------------------------------------
Every vendor publishes its own crawler ranges at its own URL, updates them on
its own schedule, and states that a crawler is only genuine if the *forward*
and *reverse* DNS both match. A list frozen into the source tree is wrong
within weeks and nobody notices, because a stale range silently widens the
trust boundary. So the default ships empty and this pulls the current lists
on demand.

The list is a necessary but not sufficient check: it proves the request came
from a range the vendor publishes, not that the User-Agent header is honest.
That is the same trust level nginx's real_ip / geoip work at, and it is why
the exemption is limited to soft rule categories (see
core/ip_reputation.is_crawler_exempt) — an attack rule still blocks a crawler
carrying an injection payload.

Usage
-----
    python3 tools/fetch_crawler_ips.py                 # print JSON to stdout
    python3 tools/fetch_crawler_ips.py --config /opt/verynginx/configs/config.json
    python3 tools/fetch_crawler_ips.py --apply         # write into the config
    python3 tools/fetch_crawler_ips.py --only google,bing

A source that cannot be reached is reported and skipped; it is never silently
replaced by a remembered value. Run with --apply only when at least one source
succeeded, and review the diff — a partial fetch would otherwise look like the
vendor shrank its range.
"""

import argparse
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126 Safari/537.36")

IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# key -> (url, json_pointer_or_None, note)
# json_pointer: dotted path into a decoded document whose prefixes are NOT
# reachable by _json_v4's shape probing (plain-text sources leave it None).
#
# Four of these publish a machine-readable JSON. Baidu cannot be fetched and is
# listed so the failure is expected and explained rather than looking like a
# bug: it publishes no public range file at all — its documented check is
# reverse DNS plus a forward-confirming lookup, with the ranges visible only
# inside the logged-in webmaster portal. Third party "Baiduspider IP段" blog
# posts are exactly the kind of remembered list this tool exists to avoid.
#
# Note on sizes: DuckDuckGo publishes several hundred individual /32s, so the
# merged list runs to ~700 entries and match_any() walks all of them on a bot
# rule match. Measured against the real 708-entry list on this box: 156 us for
# a full miss, 124 us for a Google /27 hit, and ~1 us when an early entry
# matches on string equality. That path is only reached once a bot rule's
# matcher has already matched, so it is a rare request, and the narrow /32s
# mean the exemption grants nothing beyond the exact addresses DuckDuckGo says
# it crawls from.
SOURCES = {
    "google":  ("https://developers.google.com/static/crawling/ipranges/common-crawlers.json", None,
                "Googlebot, Google-InspectionTool, GoogleOther, Google-Read-Aloud, "
                "Google-Extended, Storebot-Google, GoogleProducer, APIs-Google"),
    "bing":    ("https://www.bing.com/toolbox/bingbot.json", None, "Bingbot"),
    "apple":   ("https://search.developer.apple.com/applebot.json", None, "Applebot"),
    "duckduckgo": ("https://duckduckgo.com/duckduckbot.json", None, "DuckDuckBot"),
    "baidu":   ("https://ziyuan.baidu.com/ziyuan/help", None,
                "Baiduspider — no public range file; reverse-DNS + forward confirm"),
}


def _get(url, timeout=25):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _pluck(text, pointer):
    if pointer is None:
        return text
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text
    cur = data
    for part in pointer.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return text
    return cur if isinstance(cur, (list, str)) else text


def _json_v4(data):
    """Pull the IPv4 prefixes out of a decoded crawler-range document.

    Two shapes are in the wild and neither is guessable from the other:
      * Google's common-crawlers.json — {"prefixes": [{"ipv4Prefix": ...},
                                                     {"ipv6Prefix": ...}]}
        i.e. a flat array tagged per entry by key name.
      * {"prefixes": {"IPv4": [...], "IPv6": [...]}} — bucketed by version.
    Probing for the first that actually yields addresses keeps a vendor
    re-shaping its JSON from silently emptying the list.
    """
    if not isinstance(data, dict):
        return []
    prefixes = data.get("prefixes", data)
    if isinstance(prefixes, dict):
        for key in ("IPv4", "ipv4", "ipv4Prefix", "prefixesIPv4"):
            if isinstance(prefixes.get(key), list):
                return [x for x in prefixes[key] if isinstance(x, str)]
        return []
    if isinstance(prefixes, list):
        out = []
        for entry in prefixes:
            if isinstance(entry, str):
                out.append(entry)
            elif isinstance(entry, dict):
                # Accept ipv4Prefix / ipv4_prefix / any *4* tagged key.
                for key, val in entry.items():
                    if isinstance(val, str) and ("ipv4" in key.lower()
                                                 or key.lower().startswith("ipv4")):
                        out.append(val)
        return out
    return []


def _normalize(items):
    """Keep well-formed bare addresses and CIDRs; drop everything else.

    Tokens are matched EXACTLY, never as substrings. A regex sweep over the
    raw page also matches the network address inside "103.21.244.0/22", which
    would add a /32 trust entry next to the /22 it came from — and worse, it
    would happily turn any IP mentioned in surrounding prose into one.
    """
    out = set()
    for raw in items:
        for tok in re.split(r"[\s,;\"'\[\]<>]+", str(raw)):
            tok = tok.strip().rstrip(".")
            if not tok:
                continue
            if "/" in tok:
                net, _, bits = tok.partition("/")
                if not bits.isdigit() or not (1 <= int(bits) <= 32):
                    continue
                if not _ok_v4(net):
                    continue
                # A netblock with host bits set is ambiguous; normalise it so
                # the file reads the same way every time it is regenerated.
                octets = [int(x) for x in net.split(".")]
                value = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
                size = 1 << (32 - int(bits))
                value -= value % size
                out.add("%d.%d.%d.%d/%d" % (value >> 24 & 255, value >> 16 & 255,
                                           value >> 8 & 255, value & 255, int(bits)))
            elif _ok_v4(tok):
                out.add(tok + "/32")
    return sorted(out, key=lambda c: [int(x) for x in c.split("/")[0].split(".")])


def _ok_v4(s):
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
    return True


def fetch(only=None):
    result, failures = {}, []
    for key, (url, pointer, note) in SOURCES.items():
        if only and key not in only:
            continue
        try:
            body = _get(url)
        except Exception as exc:                      # noqa: BLE001
            failures.append((key, url, str(exc)))
            print("  [FAIL] %-11s %s — %s" % (key, url, exc), file=sys.stderr)
            continue
        cidrish = None
        try:
            decoded = json.loads(body)
        except json.JSONDecodeError:
            decoded = None
        if decoded is not None:
            # Structured source: read exactly the IPv4 fields. A regex sweep
            # over the serialised JSON would also pick up the ipv6Prefix
            # values and mangle them into IPv4-shaped garbage.
            v4 = _json_v4(decoded)
            cidrish = "\n".join(v4) if v4 else ""
            stamp = decoded.get("creationTime") if isinstance(decoded, dict) else None
        else:
            cidrish = _pluck(body, pointer)
            stamp = None
        cidrish = re.sub(r"(?m)^#.*$", "", cidrish)   # drop comment lines
        # Hand the text to the exact-token matcher. Substring extraction
        # here would double-count every CIDR's network address as a /32.
        nets = _normalize([cidrish])
        if not nets:
            failures.append((key, url, "no parseable IPv4 ranges in response"))
            print("  [WARN] %-11s %s — parsed 0 ranges (JS-rendered page?)" % (key, url),
                  file=sys.stderr)
            continue
        result[key] = {"url": url, "note": note, "nets": nets, "published_at": stamp}
        print("  [ OK ] %-11s %-3d ranges  %s%s" % (
            key, len(nets), url, "  (published %s)" % stamp if stamp else ""),
            file=sys.stderr)
    return result, failures


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="/opt/verynginx/configs/config.json")
    ap.add_argument("--apply", action="store_true",
                    help="write crawler_ip_whitelist into the config file")
    ap.add_argument("--only", help="comma-separated subset of: " + ",".join(SOURCES))
    args = ap.parse_args()

    only = set(args.only.split(",")) if args.only else None
    print("Fetching crawler ranges...", file=sys.stderr)
    result, failures = fetch(only)

    if not result:
        print("\nNo source returned a usable list. Nothing was written — a "
              "remembered list would be a guess, and a guess here is a trust "
              "boundary.\nRun this from a host that can reach the vendor URLs, "
              "or paste the ranges into ip_reputation.crawler_ip_whitelist by hand.",
              file=sys.stderr)
        return 2

    merged, provenance = [], []
    for key in sorted(result):
        merged.extend(result[key]["nets"])
        provenance.append({"source": key, "url": result[key]["url"],
                           "note": result[key]["note"],
                           "count": len(result[key]["nets"]),
                           # When the vendor dates its own list, keep that date:
                           # Bing's has read 2024-01-03 for a long time, and
                           # knowing a list is stale is different from not
                           # knowing it exists.
                           "published_at": result[key].get("published_at"),
                           "fetched_at": datetime.now(timezone.utc).isoformat()})
    merged = _normalize(merged)

    if not args.apply:
        print(json.dumps({"crawler_ip_whitelist": merged,
                          "_sources": provenance}, ensure_ascii=False, indent=2))
        return 0

    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)
    ir = cfg.setdefault("ip_reputation", {})
    previous = ir.get("crawler_ip_whitelist") or []
    ir["crawler_ip_whitelist"] = merged
    ir["crawler_ip_whitelist_sources"] = provenance
    # Deliberately does NOT touch ir["enable"]: this tool is about crawler
    # ranges, and flipping the reputation switch on someone's behalf would be
    # a change they never asked for.

    tmp = args.config + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=4)
        f.write("\n")
    import os
    os.replace(tmp, args.config)

    print("\nwrote %d ranges to %s (was %d)" % (len(merged), args.config, len(previous)),
          file=sys.stderr)
    if failures:
        print("%d source(s) failed — the list below is INCOMPLETE. Re-run for those "
              "before trusting it:" % len(failures), file=sys.stderr)
        for key, url, why in failures:
            print("  %-11s %s  (%s)" % (key, url, why), file=sys.stderr)
    print("Reload VeryNginx for the change to take effect.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
