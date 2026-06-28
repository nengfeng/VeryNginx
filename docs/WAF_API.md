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

Returns runtime stats for a single rule.

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
