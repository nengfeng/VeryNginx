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

### Reverse Proxy

- **Dynamic upstreams** — add/remove nodes via dashboard, no reload required
- **Health checks** — periodic HTTP/HTTPS probes with configurable thresholds
- **DNS caching** — resolves hostnames at startup, respects TTL, round-robins across A records
- **Load balancing** — weighted round-robin with automatic unhealthy-node removal
- **WebSocket support** — seamless Upgrade/Connection header passthrough
- **TLS/SSL to upstream** — SNI, certificate verification support

### Management

- **Web dashboard** — full configuration at `/verynginx/index.html`
- **Hot-reload** — config changes take effect immediately (zero-I/O MD5 hash comparison)
- **Atomic saves** — `tmp + rename` strategy with automatic backups (keeps last 10)
- **Prometheus metrics** — `/verynginx/metrics` endpoint for monitoring
- **Request statistics** — per-URI tracking across 1m/5m/1h/all time windows

### Security

- **Session authentication** — PBKDF2-HMAC-SHA256 password hashing (optional bcrypt/argon2)
- **CSRF protection** — enabled by default for all configuration endpoints
- **Configurable request body limits** — size, argument count, error policy (fail-closed/match/skip)

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
| [Usage Manual](docs/USAGE_zh.md) | matchers, rules, upstreams, plugins, statistics, security |
| [Architecture Design](docs/DESIGN_V2.md) | v2 design: plugin system, config management, request lifecycle |

---

## License

[VeryNginx License](LICENSE.txt)
