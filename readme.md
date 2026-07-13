# VeryNginx v2

A powerful, extensible WAF (Web Application Firewall), reverse proxy, and request management engine built on Nginx + Lua.

[中文文档](readme_zh.md) | [Installation Guide](docs/INSTALL_zh.md) | [Usage Manual](docs/USAGE_zh.md) | [Architecture Design](docs/DESIGN_V2.md)

---

## Features

### Web Application Firewall (WAF)

- **Plugin-based architecture** — filter, frequency_limit, browser_verify, proxy_pass, static_file, router, summary
- **10 matcher types** — IP (CIDR), Host, URI, UserAgent, Referer, Args, Header, Cookie, Method, Composite
- **8 rule groups** — filter, frequency_limit, browser_verify, proxy_pass, static_file, redirect, uri_rewrite, scheme_lock
- **Pre-built WAF rules** — SQL injection, path traversal, scanner detection, Git/SVN exposure
- **Browser verification** — cookie + JavaScript challenge against bots and CC attacks
- **Rate limiting** — per-IP, per-URI, or custom key with configurable time windows
- **Rule staging / approval flow** — changes can be staged as "pending" before activation
- **Rule effectiveness scoring** — grades (A+/A/B/C/D) based on challenge pass rates and hit counts
- **Dead rule detection** — flags rules with zero hits in 30 days for review or cleanup
- **Attack timeline** — stacked bar chart of blocked attacks by category over time (color-coded)
- **Hit detail drill-down** — click any hit to see full request context (UA, headers, body, IP reputation)
- **Rule test history** — automatic save of last 20 test runs for comparison and debugging
- **Test rule against cases** — built-in tester with request samples and match results
- **IP reputation engine** — scoring based on signals (WAF block/challenge/404), auto-flagging, whitelist, challenge flow
- **TLS fingerprinting (JA3)** — client identification via TLS handshake fingerprint (graceful fallback to simple TLS params)

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
- **Prometheus metrics** — `/verynginx/metrics` endpoint for monitoring (per-rule hits/blocks/challenges, plugin duration, IP reputation)
- **Request statistics** — per-URI tracking across 1m/5m/1h/all time windows
- **Audit log** — ring buffer (1000 entries) with search by user, action type, and time range
- **Alerting engine** — webhook notifications for hit rate spikes, false positive changes, unknown attack patterns, JA3 cross-IP correlation
- **Frequency limit management** — dedicated dashboard page for rate limit rules and active counters

### Security

- **Session authentication** — PBKDF2-HMAC-SHA256 password hashing (optional bcrypt/argon2), 8h default TTL
- **CSRF protection** — enabled by default for all configuration endpoints
- **Configurable request body limits** — size, argument count, error policy (fail-closed/match/skip)
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
