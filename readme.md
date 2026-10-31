# VeryNginx v2

A powerful, extensible WAF (Web Application Firewall), reverse proxy, and request management engine built on Nginx + Lua.

[中文文档](readme_zh.md) | [Installation Guide](docs/INSTALL_zh.md) | [Usage Manual](docs/USAGE_zh.md) | [Architecture Design](docs/DESIGN_V2.md)

## v2.3 Highlights (2026-10-13)

- **Request-body inspection rebuilt** — `multipart/form-data` field names *and* values now reach the WAF (file contents skipped), after closing three P0 parser bypasses and a parameter-name blind spot. New `body.max_field` (field length cap, independent of `max_size`), `body.scan_exempt` (URI exemptions, case-insensitive, e.g. phpMyAdmin), and `body.on_error` defaulting to `log` with a ModSecurity *ProcessPartial* prefix scan — oversized uploads are neither read whole nor silently unscanned.
- **Default ruleset hardened v9 → v17** — ssrf category added, scanner-bypass paths closed, ffuf's real default UA finally matched, admin-path exemptions accept `.php` entries (`/adminer.php`), and the sqli/xss/ssrf/rce rules rebuilt over three external reviews: `UNION(SELECT)`/`UNION DISTINCT` match, tautology gaps closed (comment obfuscation, `LIKE`/`IN`/`BETWEEN`), tutorial-prose false positives cut, the XSS event table completed, `javascript:` rebuilt around code shape, SSRF covers `user@` prefixes. `vn_rce_0007` settled as a value-anchored block (leading separator + 24 high-risk bare-invocation commands, no argument guard — so `data:` URIs and CSV never block while `; rm file` does) with a log-only companion rule; a "value must not contain non-ASCII" style guard was banned outright after it was shown to be a universal bypass switch (append one high byte and every payload goes clean).
- **TLS fingerprinting on JA4, and two chains that never ran** — the old path read `$ssl_client_j3_hash` (undefined on a vanilla nginx: no JA3 module compiled in) and the filter plugin consulted a `ctx.request.ja3_fingerprint` key nothing ever wrote, so fingerprint blocking, challenging and cross-IP alerting had never actually fired. JA4 is now computed once per handshake (the only context that sees the raw ClientHello), needs no nginx rebuild, and is stable under GREASE randomisation. Library entries carry **kind** (ja3/ja4/ja4h) and **match mode** (exact/family); matching is kind-scoped, the negotiated-cipher `tls:` namespace is explicitly non-matchable, and family matching slices the human-readable section A so a client survives its own cipher rotation. `tools/import_ja4db.py` turns the official FoxIO mapping into candidates (**log by default**, hashes shared with benign clients skipped).
- **Factory-drift transparency** — an endpoint reports content/action/missing drift against the factory ruleset, the dashboard explains gray-release vs stale actions, and each drifted rule can be individually "accepted" back to factory action; `restore-defaults` only re-adds missing factory rules by id and never overwrites operator-set actions.
- **IP reputation observability** — flagged IPs now carry reasons, drill-down into the score history, optional IP-quality lookup, and a durable per-day flag log (48h) with a hard write-path cap (its unbounded growth ran O(n) inside the global index lock on the request hot path and could freeze the index).
- **Per-host request statistics** — the request panel can filter and aggregate by host.
- **Dashboard history tab redesigned around undo** — rollback is undoable, deletions restore per-entry; factory-drift hints and per-rule accept-action live next to it.
- **Operational fixes** — GeoIP validation and mirror download reporting, lua-resty-http 0.18.0, installer preserves runtime config on upgrade, fresh installs auto-configure Cloudflare real client IP (`http_realip_module` with the official ranges), and `upgrade.sh` re-injects the TLS fingerprint hook so upgraded installs actually get it.
- **Standing gates** — every factory rule ships with a PCRE positive/negative battery (`test/v2/factory_rules_battery.py`, 477 checks covering every command family, dual-engine verified against real PCRE), the vendored JA4 implementation is pinned to FoxIO's published vectors (`test/v2/ja4_golden.lua`), plus luacheck 0/0 over 113 files, 433 spec and 481 phase0 cases, and dashboard binding gates.

---

## v2.2 Highlights (2026-09-06)

- **Security audit remediation (35 findings closed)**: session/password constant-time compare rewritten (the old algebraic identity allowed admin-session forgery at ~1/20,000 per try); upstream TLS verification for proxied backends (self-signed upstreams need an explicit CA); `configs/` permission hardening — no more world-readable `session_secret`; proxy-path crash and internal-redirect-loop fixes (the proxy chain had never been end-to-end exercised); request-time JSON hardening — malformed `POST /config` bodies now 400, not 500
- **Stricter contracts**: proxy rules must declare `action`; whitelist CIDRs at or below /8 rejected (they neutralize kernel blocking); frequency rule ids validated; composite (AND/OR/NOT) matchers validated recursively; systemd-helper fixes (reconcile guards, conn deadline, flush scope, allow-prefix floor)
- **Upgrade trust model**: `upgrade.sh` pins the deployed commit (anchored at install time, self-updates from verified checkouts), reports staleness against the branch, rebuilds the firewall helper on upgrade, and forbids the `curl | bash` flow that let branch writers control the pin
- **Supply chain**: checksum-pinned OpenResty/Go downloads; Debian base moved to bookworm (bullseye EOL); installer privilege fixes
- **Quality gates**: luacheck over every Lua file (incl. lifecycle entry points), busted spec + phase0 suites and Go helper tests now run in CI (216 spec / 329 phase0 cases, 10 Go test files green), install-time SRI self-check, dashboard version metadata fixed (`dev` no more)
- **Boot reliability**: init-phase guard for webhook DNS validation (a domain-shaped webhook no longer bricks nginx startup via cosocket-in-init), static file serving is byte-faithful (`ngx.print`, not `ngx.say` + stray newline)
- **Installer hardening**: resolver injection for cosocket DNS, `lua_ssl_trusted_certificate` for outbound TLS, SRI pin-vs-served drift detection, reinstall blind-spot cleanup, self-check port-000 attribution
- **Security**: SSRF guards for IPv6 bracket/mapped literal forms, fail-closed coverage for empty `session_secret`, audit-leftover cleanup batch
- **Dashboard stability**: full `asList` sanitization sweep plus static gates that pin template bindings == exports, reactive table tools fix, uBlock-safe module rename (`vn-iploc.js`)
- **WAF rule tester**: form-based testing (no hand-written JSON), one-click load of existing rules, paste-access-log case generation
- **Testing**: 199 spec + 317 phase0 green; new regression suites (init-phase webhook, byte fidelity, sanitizer contracts)

---

## v2.1 Highlights (2026-08-16)

- **Performance optimizations**: Per-rule WAF stats via index (no more `get_keys` 200-key ceiling), cached `is_v2_active()` and `is_whitelisted()` generation reads, score cache fast-path in IP reputation collection
- **Race condition fixes**: Atomic index updates for `waf_rule_stats` and `metrics` (token-verified locks), `flush_hit_stats` timer now worker-0 only (prevents double-counting)
- **Security hardening**: `session_secret` redacted in `/config` and `/config/export`; config save restores `session_secret` from sentinel; case-insensitive IPv6 private address detection in SSRF guard
- **Kernel blocking robustness**: Per-worker IPC mutex with token ownership, `close_socket_no_backoff` guards scope binding, generation bump under config save lock
- **Observability improvements**: Prometheus export uses index-only (no `get_keys` fallback); shared dict usage alerting includes `metrics_labeled`
- **Schema integrity**: `frequency_limit` template CIDR rejected (matcher has no CIDR semantics); `config.whitelist` entry format validated on save

---

## Features

### Web Application Firewall (WAF)

- **Plugin-based architecture** — filter, frequency_limit, browser_verify, proxy_pass, static_file, router, summary
- **10 matcher types** — IP (CIDR), Host, URI, UserAgent, Referer, Args, Header, Cookie, Method, Composite
- **8 rule groups** — filter, frequency_limit, browser_verify, proxy_pass, static_file, redirect, uri_rewrite, scheme_lock
- **Pre-built WAF rules** — 26 factory rules across sqli / xss / rce / lfi / path_traversal / ssrf / scanner / bot / brute / spam / crlf / deserialization, ship as editable JSON with the dashboard's factory-drift view
- **Browser verification** — cookie + JavaScript challenge against bots and CC attacks
- **Rate limiting** — per-IP, per-URI, or custom key with configurable time windows
- **Rule staging / approval flow** — changes can be staged as "pending" before activation
- **Rule effectiveness scoring** — grades (A+/A/B/C/D) based on challenge pass rates and hit counts
- **Dead rule detection** — flags rules with zero hits in 30 days for review or cleanup
- **Attack timeline** — stacked bar chart of blocked attacks by category over time (color-coded)
- **Hit detail drill-down** — click any hit to see full request context (UA, headers, body, IP reputation)
- **Rule test history** — automatic save of last 20 test runs for comparison and debugging
- **Test rule against cases** — built-in tester with request samples and match results
- **IP reputation engine** — scoring based on signals (WAF block/challenge/404), auto-flagging, whitelist, challenge flow, with flag reasons and a per-day flag log
- **TLS fingerprinting (JA4)** — client identification via the TLS ClientHello fingerprint, computed in the handshake phase (`ssl_client_hello_by_lua*`), stable across GREASE randomisation; no nginx rebuild required. Library entries are kind-scoped (`ja3`/`ja4`/`ja4h`) and support exact or family (section-A prefix) matching; the negotiated-cipher fallback is recorded but never matched. JA4H (HTTP-layer) is available behind `fingerprints.ja4.http_enable`

### Reverse Proxy

- **Dynamic upstreams** — add/remove nodes via dashboard, no reload required
- **Health checks** — periodic HTTP/HTTPS probes with configurable thresholds
- **DNS caching** — resolves hostnames at startup, respects TTL, round-robins across A records
- **Load balancing** — weighted round-robin with automatic unhealthy-node removal
- **WebSocket support** — seamless Upgrade/Connection header passthrough
- **TLS/SSL to upstream** — SNI, certificate verification support

### Kernel IP Blocking

- **WAF-to-kernel promotion** — confirmed malicious IPs (scanner/CC) promoted from WAF to Linux nftables kernel firewall via Go Helper
- **Four logical sets** — `scanner_drop`, `cc_drop`, `manual_drop`, `allow` with atomic nft transaction
- **Privileged Helper** — Go static binary with Unix Domain Socket IPC (Protocol v1); only `CAP_NET_ADMIN` required (no root)
- **Canary deployment** — initial short TTL (60s scanner / 30s CC) with automatic escalation to full TTL on high-confidence signals
- **Emergency break-glass** — pause/resume promotion, flush auto-owned entries, manual IP block/clear
- **Fail-open design** — any Helper error preserves existing Lua WAF; no single point of failure
- **Dashboard + API** — full management UI tab and 10 REST endpoints (`/kernel-blocking/status`, `/entries`, `/candidates`, `/promote`, `/clear`, `/pause`, `/flush-auto`, `/reconcile`, `/bucket-history`, `/diff`)
- **Auto whitelist sync** — static + auto-whitelist pushed to Helper via generation-qualified cache

### Management

- **Web dashboard** — full configuration at `/verynginx/index.html` (configurable `base_uri`)
- **Dark mode** — built-in dark theme with system preference detection and localStorage persistence
- **Hot-reload** — config changes take effect immediately (zero-I/O MD5 hash comparison)
- **Atomic saves** — `tmp + rename` strategy with automatic backups (keeps last 10)
- **Prometheus metrics** — `/verynginx/metrics` endpoint for monitoring (per-rule hits/blocks/challenges, plugin duration, IP reputation). **Auth required since the persistence audit** — scrape with a dashboard session cookie or forward via an internal channel.
- **Request statistics** — per-URI tracking across 1m/5m/1h/all time windows, with per-host filtering
- **Audit log** — ring buffer (1000 entries) with search by user, action type, and time range
- **Alerting engine** — webhook notifications for hit rate spikes, false positive changes, unknown attack patterns, TLS-fingerprint cross-IP correlation (distributed-scanner detection)
- **Frequency limit management** — dedicated dashboard page for rate limit rules and active counters

### Security

- **Session authentication** — PBKDF2-HMAC-SHA256 password hashing (optional bcrypt/argon2), 8h default TTL
- **CSRF protection** — enabled by default for all configuration endpoints
- **Configurable request body limits** — size, field length, argument count, URI exemptions (`body.scan_exempt`, case-insensitive) and error policy (fail-closed/match/skip/log, with ProcessPartial prefix scanning for oversized bodies)
- **Account lockout** — 5 failed logins locks the account for 15 minutes
- **Rate limiting** — IP-based (30/min) and per-user (5/min) login protection
- **Audit log filtering** — search by user, action type, and time range for security investigations
- **SSRF protection** — webhook URLs validated (HTTPS-only, no internal IPs) at storage and runtime

---

## Quick Start

```bash
# Install (OpenResty + VeryNginx)
python install.py install

# Set admin password
python install.py hash-password your_password

# Start
/opt/verynginx/openresty/nginx/sbin/nginx
```

Visit `http://<your-server>/verynginx/index.html`

### Using your own Nginx?

VeryNginx v2 also works with standard **Nginx + lua-nginx-module + lua-resty-core** — no full OpenResty required. See [Installation Guide](docs/INSTALL_zh.md) for details.

### Docker

```bash
docker build -t verynginx .
docker run -d --name=verynginx -p 8080:80 verynginx
```

---

## Architecture Overview

```
Request → rewrite phase → access phase → balancer → proxy_pass → log phase
```

1. **rewrite_by_lua** — hot-reload check, request context creation, scheme/redirect/rewrite
2. **access_by_lua** — plugin execution (filter → frequency_limit → browser_verify → router → proxy_pass → static_file → summary), with short-circuit on terminal actions
3. **balancer_by_lua** — dynamic upstream peer selection with health awareness
4. **proxy_pass** — reverse proxy with WebSocket, TLS, DNS support
5. **log_by_lua** — statistics collection, metric emission

### Configuration Flow

```
Dashboard / API → validate → normalize defaults → backup current → atomic write → activate snapshot
```

All other Nginx workers detect the change via MD5 hash in shared memory (zero file I/O) on the next request.

---

## Documentation

| Document | Description |
|---|---|
| [Installation Guide](docs/INSTALL_zh.md) | install.py, manual Nginx, Docker, and post-install setup |
| [Usage Manual](docs/USAGE_zh.md) | matchers, rules, upstreams, plugins, statistics, security, dashboard features |
| [Architecture Design](docs/DESIGN_V2.md) | v2 design: plugin system, config management, request lifecycle |
| [Kernel IP Blocking Design](docs/KERNEL_IP_BLOCKING_DESIGN.md) | kernel-level IP blocking: promotion policy, nftables execution, IPC protocol |
| [Kernel IP Blocking Plan](docs/KERNEL_IP_BLOCKING_IMPL_PLAN.md) | implementation phases: evidence, observe, shadow, canary, install |
| [IP Reputation Tuning](docs/IP_REPUTATION_TUNING_GUIDE.md) | production tuning: thresholds, false positive troubleshooting, pending TTL coordination |
| [WAF API Reference](docs/WAF_API.md) | REST API for rule management, testing, statistics, and analytics |

---

## License

[VeryNginx License](LICENSE.txt)
