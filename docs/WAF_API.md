# VeryNginx v2 WAF Rule Management API

All endpoints require authentication (except where noted) and return JSON.

**Base URL**: `{base_uri}/waf/` (default: `/verynginx/waf/`)

**Common Response Format**:
- Success: `{ "ret": "success", "data": {...} }`
- Error: `{ "ret": "failed", "message": "error description" }`

---

## Rules

### List Rules

```
GET /verynginx/waf/rules?category=sqli&severity=critical&page=1&limit=20
```

**Query Parameters**:
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `category` | string | - | Filter by category (sqli, xss, etc.) |
| `severity` | string | - | Filter by severity (critical, high, medium, low) |
| `page` | number | 1 | Page number |
| `limit` | number | 20 | Items per page (max 100) |

**Response**:
```json
{
  "ret": "success",
  "data": {
    "rules": [{ ... }],
    "pagination": { "page": 1, "limit": 20, "total": 6, "total_pages": 1 },
    "categories": { "sqli": 2, "xss": 1 }
  }
}
```

### Create Rule

```
POST /verynginx/waf/rules
Content-Type: application/json

{ "name": "...", "category": "sqli", "severity": "critical", ... }
```

**Required Fields**: `name`, `category`, `severity`, `action`, `matcher`

### Get Rule

```
GET /verynginx/waf/rules/{id}
```

Returns the full rule object including runtime stats (hit_count, last_triggered).

### Update Rule

```
PUT /verynginx/waf/rules/{id}
Content-Type: application/json

{ "severity": "high", "description": "Updated" }
```

Partial update. Runtime stats (hit_count, etc.) are preserved.

### Delete Rule

```
DELETE /verynginx/waf/rules/{id}
```

Returns 200 on success.

### Enable / Disable Rule

```
POST /verynginx/waf/rules/{id}/enable
POST /verynginx/waf/rules/{id}/disable
```

---

## Testing

### Test Rule

```
POST /verynginx/waf/rules/test
Content-Type: application/json

{
  "rule": { "matcher": { ... }, "action": "block" },
  "test_cases": [
    { "name": "normal", "uri": "/api/users", "expected": false },
    { "name": "attack", "uri": "/api/attack", "expected": true }
  ]
}
```

**Response**:
```json
{
  "ret": "success",
  "data": {
    "total": 2, "passed": 2, "failed": 0,
    "results": [
      { "name": "normal", "uri": "/api/users", "matched": false, "passed": true },
      { "name": "attack", "uri": "/api/attack", "matched": true, "passed": true }
    ]
  }
}
```

---

## Versioning

### Reload from File

```
POST /verynginx/waf/rules/reload
```

Force reload rules from `configs/waf-rules.json`. Returns 400 if file is missing.

### Get History

```
GET /verynginx/waf/rules/history?limit=50
```

Returns version history (metadata only, no full rule data).

### Rollback

```
POST /verynginx/waf/rules/rollback
Content-Type: application/json

{ "version": 3, "rule_id": "sqli_001" }
```

`rule_id` is optional — if provided, verifies the rule exists in the target version.

---

## Statistics

### Aggregate Stats

```
GET /verynginx/waf/stats
```

**Response**:
```json
{
  "ret": "success",
  "data": {
    "total_rules": 6,
    "enabled_rules": 5,
    "total_hits": 5234,
    "today_hits": 156,
    "by_category": { "sqli": { "rules": 2, "hits": 2345 }, ... },
    "by_severity": { "critical": { "rules": 3, "hits": 3456 }, ... },
    "top_rules": [
      { "id": "sqli_001", "name": "SQL Injection", "hits": 1523 }
    ]
  }
}
```

### Rule Stats

```
GET /verynginx/waf/stats/{id}
```

Returns runtime stats for a single rule (hit_count, block_count, challenge_count).

---

## Analytics

### Rule Effectiveness Scoring

```
GET /verynginx/waf/analytics
```

Returns per-rule effectiveness grades, hit/challenge/pass counts, and dead rule detection.

**Response**:
```json
{
  "ret": "success",
  "data": {
    "rules": [
      {
        "id": "attack_sqli",
        "name": "SQL Injection",
        "action": "block",
        "hits": 1420,
        "blocks": 1420,
        "challenges": 0,
        "challenge_passes": 0,
        "challenge_pass_rate": "-",
        "grade": "A+",
        "dead": false,
        "last_triggered": 1719000000,
        "last_triggered_ago": 3600
      }
    ],
    "dead_rules": [
      { "id": "attack_xxe", "name": "XXE", "enable": false, "hits": 0 }
    ]
  }
}
```

**Grades**: A+ (pure block) / A (low pass rate) / B (medium) / C (high pass rate, possible false positives) / N/A (no data).

### Attack Timeline

```
GET /verynginx/waf/timeline?hours=1&bucket=5
```

Aggregated blocked hits by time bucket and category.

**Query Parameters**:
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `hours` | number | 1 | Time window (1-24) |
| `bucket` | number | 5 | Bucket size in minutes (1-30) |

**Response**:
```json
{
  "ret": "success",
  "data": {
    "buckets": [{ "time": 1719000000, "counts": { "sqli": 5, "scanner": 2 } }],
    "categories": ["sqli", "scanner"],
    "bucket_minutes": 5,
    "hours": 1
  }
}
```

### Hit Detail (Drill-down)

```
GET /verynginx/waf/hits/{ring_idx}
```

Returns full request context for a specific hit, enriched with rule metadata and IP reputation.

**Response**:
```json
{
  "ret": "success",
  "data": {
    "rule_id": "attack_sqli",
    "rule_name": "SQL Injection",
    "rule_category": "sqli",
    "timestamp": 1719000000,
    "ip": "1.2.3.4",
    "method": "GET",
    "uri": "/api/user?id=1' OR '1'='1",
    "user_agent": "Mozilla/5.0...",
    "headers": { "Accept": "application/json", "Cookie": "..." },
    "body_snippet": "",
    "action": "block",
    "ip_score": 30,
    "ip_flagged": true,
    "ip_whitelisted": false,
    "ip_hit_count": 23,
    "ja3_fingerprint": "ja3:abc123..."
  }
}
```

### Hits by IP

```
GET /verynginx/waf/hits/by-ip?ip=1.2.3.4
```

Returns all recent hits from a specific IP address.

### Test History

```
GET /verynginx/waf/test-history
```

Returns the last 20 test runs with rule name, pass/fail counts, and individual results.

```
DELETE /verynginx/waf/test-history
```

Clears all test history.

---

## Frequency Limit

### List Rules

```
GET /verynginx/frequency/rules
```

Returns all frequency limit rules from config.

### Save Rule

```
POST /verynginx/frequency/rules
Content-Type: application/json

{ "id": "freq_login", "key": "ip", "limit": 60, "window": 60, "code": 429 }
```

### Delete Rule

```
DELETE /verynginx/frequency/rules/{freq_login}
```

### Active Counters

```
GET /verynginx/frequency/stats
```

Returns active rate limit counters (top 200 by count).

---

## Audit

```
GET /verynginx/audit?user=&action=&since=&until=&limit=500
```

Returns audit log entries, filterable by user, action type, and time range.

**Query Parameters**:
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `user` | string | - | Filter by username |
| `action` | string | - | Filter by action type |
| `since` | number | - | Unix timestamp, start of range |
| `until` | number | - | Unix timestamp, end of range |
| `limit` | number | 200 | Max results (max 1000) |

---

## Error Codes

| HTTP Status | Meaning |
|-------------|---------|
| 200 | Success |
| 400 | Bad request (invalid JSON, missing fields, validation error) |
| 401 | Unauthorized (missing or invalid session) |
| 404 | Rule not found |
| 429 | Rate limited |

---

## Rate Limiting

All authenticated API endpoints are rate-limited to 60 requests per 60 seconds per user. Config saves are limited to 30 per 60 seconds.
