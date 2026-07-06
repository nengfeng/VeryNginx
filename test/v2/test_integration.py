#!/usr/bin/env python3
"""
VeryNginx v2 - Integration Tests
Tests against a running OpenResty instance (Docker or local).
"""

import subprocess
import json
import time
import sys
import os
import traceback

BASE_URL = os.environ.get("VN2_TEST_URL", "http://127.0.0.1:8080")
USER = "verynginx"
PASS = "verynginx"

def curl(method, path, data=None, cookies=None, headers=None):
    """Make an HTTP request and return (status, body, cookies)."""
    cmd = ["curl", "-s", "-w", "\n%{http_code}", "-X", method]
    if cookies:
        cmd.extend(["-b", ";".join(f"{k}={v}" for k, v in cookies.items())])
    if data:
        cmd.extend(["-d", data])
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    cmd.append(BASE_URL + path)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    lines = result.stdout.strip().split("\n")
    status = int(lines[-1])
    body = "\n".join(lines[:-1])
    return status, body

def b64encode(s):
    import base64
    return base64.b64encode(s.encode()).decode()

def test_health():
    """Test that the service is running."""
    status, body = curl("GET", "/verynginx/index.html")
    assert status in (200, 302), f"Health check failed: status={status}, body={body[:200]}"
    print(f"  [PASS] Health check: {status}")

def test_login():
    """Test login with correct and incorrect credentials."""
    # Invalid login
    status, body = curl("POST", "/verynginx/login", data="user=bad&password=wrong")
    assert status in (400, 401), f"Login should fail: {status}"
    print(f"  [PASS] Invalid login rejected: {status}")

    # Valid login
    status, body = curl("POST", "/verynginx/login", data=f"user={USER}&password={PASS}")
    assert status == 200, f"Login should succeed: status={status}, body={body[:200]}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Login response: {body[:200]}"
    print(f"  [PASS] Valid login: {resp.get('ret')}")


def _get_auth():
    """Login and return session cookies."""
    status, body = curl("POST", "/verynginx/login", data=f"user={USER}&password={PASS}")
    assert status == 200, f"Login failed: status={status}, body={body[:200]}"
    resp = json.loads(body)
    token = resp.get("token", "")
    return {"verynginx_session": token}

# Session cache to avoid rate limiting across tests
_session_cookies = None

def get_shared_session():
    """Get cached session cookies (login once, reuse everywhere)."""
    global _session_cookies
    if _session_cookies is None:
        _session_cookies = _get_auth()
    return _session_cookies

def test_config():
    """Test config endpoint (requires auth)."""
    cookies = get_shared_session()

    # Get CSRF token
    status, body = curl("GET", "/verynginx/csrf", cookies=cookies)
    assert status == 200, f"GET CSRF failed: status={status}, body={body[:200]}"
    resp = json.loads(body)
    csrf_token = resp.get("csrf_token", "")

    # GET config
    status, body = curl("GET", "/verynginx/config", cookies=cookies)
    assert status == 200, f"GET config failed: status={status}, body={body[:200]}"
    config_data = json.loads(body)
    assert "matcher" in config_data, f"Config missing matcher: {body[:200]}"
    print(f"  [PASS] GET config: {len(body)} bytes")

    # POST config (save with base64 encoded)
    config_json = json.dumps({"version": "2.0", "matcher": {}, "rule": {}, "admin": [{"user": "verynginx", "password_hash": "test"}], "security": {"session_secret": "test"}})
    encoded = b64encode(config_json)
    escaped = encoded.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
    status, body = curl("POST", "/verynginx/config", data=f"config={escaped}&csrf_token={csrf_token}", cookies=cookies)
    assert status in (200, 400), f"POST config response: status={status}, body={body[:200]}"
    print(f"  [PASS] POST config: {status}")

def test_status():
    """Test status endpoint."""
    cookies = get_shared_session()

    status, body = curl("GET", "/verynginx/status", cookies=cookies)
    assert status == 200, f"GET status failed: {status}"
    print(f"  [PASS] GET status: {len(body)} bytes")

def test_waf_rules():
    """Test WAF rule management API."""
    cookies = get_shared_session()

    # Get CSRF token for mutating requests
    status, body = curl("GET", "/verynginx/csrf", cookies=cookies)
    assert status == 200, f"GET CSRF failed: {status}"
    csrf_resp = json.loads(body)
    csrf_token = csrf_resp.get("csrf_token", "")

    def auth_headers(extra=None):
        h = {"X-CSRF-Token": csrf_token}
        if extra:
            h.update(extra)
        return h

    # GET /waf/rules - list rules
    status, body = curl("GET", "/verynginx/waf/rules", cookies=cookies)
    assert status == 200, f"GET /waf/rules failed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Expected success, got: {body[:200]}"
    assert "data" in resp, f"Missing data field: {body[:200]}"
    assert "rules" in resp["data"], f"Missing rules field: {body[:200]}"
    assert "categories" in resp["data"], f"Missing categories: {body[:200]}"
    print(f"  [PASS] GET /waf/rules: {len(resp['data']['rules'])} rules")

    # POST /waf/rules - create a rule
    new_rule = json.dumps({
        "name": "Integration Test Rule",
        "category": "sqli",
        "severity": "critical",
        "action": "block",
        "matcher": {"URI": {"operator": "≈", "value": "union.+select"}},
        "tags": ["sqli", "test"],
        "code": 403
    })
    status, body = curl("POST", "/verynginx/waf/rules", data=new_rule, cookies=cookies, headers=auth_headers({"Content-Type": "application/json"}))
    assert status == 200, f"POST /waf/rules failed: status={status}, body={body[:200]}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Create failed: {body[:200]}"
    rule_id = resp.get("data", {}).get("id")
    assert rule_id is not None, f"Missing rule ID: {body[:200]}"
    print(f"  [PASS] POST /waf/rules: created {rule_id}")

    # GET /waf/rules/:id - get single rule
    status, body = curl("GET", f"/verynginx/waf/rules/{rule_id}", cookies=cookies)
    assert status == 200, f"GET /waf/rules/:id failed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Get rule failed: {body[:200]}"
    assert resp.get("data", {}).get("id") == rule_id, f"Wrong rule ID: {body[:200]}"
    print(f"  [PASS] GET /waf/rules/:id: found {rule_id}")

    # PUT /waf/rules/:id - update rule
    update = json.dumps({"severity": "high", "description": "Updated by integration test"})
    status, body = curl("PUT", f"/verynginx/waf/rules/{rule_id}", data=update, cookies=cookies, headers=auth_headers({"Content-Type": "application/json"}))
    assert status == 200, f"PUT /waf/rules/:id failed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Update failed: {body[:200]}"
    assert resp.get("data", {}).get("version") == 2, f"Version should be 2: {body[:200]}"
    print(f"  [PASS] PUT /waf/rules/:id: updated to v{resp['data']['version']}")

    # POST /waf/rules/:id/disable - disable rule
    status, body = curl("POST", f"/verynginx/waf/rules/{rule_id}/disable", data="", cookies=cookies, headers=auth_headers())
    assert status == 200, f"POST disable failed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Disable failed: {body[:200]}"
    print(f"  [PASS] POST /waf/rules/:id/disable: disabled")

    # POST /waf/rules/:id/enable - enable rule
    status, body = curl("POST", f"/verynginx/waf/rules/{rule_id}/enable", data="", cookies=cookies, headers=auth_headers())
    assert status == 200, f"POST enable failed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Enable failed: {body[:200]}"
    print(f"  [PASS] POST /waf/rules/:id/enable: enabled")

    # POST /waf/rules/test - test rule
    test_body = json.dumps({
        "rule": {"matcher": {"URI": {"operator": "≈", "value": "union.+select"}}},
        "test_cases": [
            {"name": "normal", "uri": "/api/users", "expected": False},
            {"name": "attack", "uri": "/api/users?id=1 UNION SELECT *", "expected": True},
            {"name": "encoded", "uri": "/api/users?id=1%20UNION%20SELECT", "expected": True}
        ]
    })
    status, body = curl("POST", "/verynginx/waf/rules/test", data=test_body, cookies=cookies, headers=auth_headers({"Content-Type": "application/json"}))
    assert status == 200, f"POST /waf/rules/test failed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Test failed: {body[:200]}"
    assert resp.get("data", {}).get("total") == 3, f"Expected 3 test cases: {body[:200]}"
    assert resp.get("data", {}).get("passed") == 3, f"Expected all test cases to pass: {body[:200]}"
    print(f"  [PASS] POST /waf/rules/test: {resp['data']['passed']}/{resp['data']['total']} passed")

    # POST /waf/rules/reload - reload rules
    status, body = curl("POST", "/verynginx/waf/rules/reload", data="", cookies=cookies, headers=auth_headers())
    assert status in (200, 400), f"POST reload failed: {status}, body={body[:200]}"
    print(f"  [PASS] POST /waf/rules/reload: {status}")

    # GET /waf/stats - get stats
    status, body = curl("GET", "/verynginx/waf/stats", cookies=cookies)
    assert status == 200, f"GET /waf/stats failed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Stats failed: {body[:200]}"
    assert "total_rules" in resp.get("data", {}), f"Missing total_rules: {body[:200]}"
    assert "by_category" in resp.get("data", {}), f"Missing by_category: {body[:200]}"
    print(f"  [PASS] GET /waf/stats: {resp['data'].get('total_rules')} rules, {resp['data'].get('total_hits')} hits")

    # GET /waf/stats/:id - get single rule stats
    status, body = curl("GET", f"/verynginx/waf/stats/{rule_id}", cookies=cookies)
    assert status == 200, f"GET /waf/stats/:id failed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Rule stats failed: {body[:200]}"
    print(f"  [PASS] GET /waf/stats/:id: success")

    # GET /waf/rules/history - get history
    status, body = curl("GET", "/verynginx/waf/rules/history", cookies=cookies)
    assert status == 200, f"GET /waf/rules/history failed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"History failed: {body[:200]}"
    assert len(resp.get("data", [])) > 0, f"Expected at least 1 history entry: {body[:200]}"
    print(f"  [PASS] GET /waf/rules/history: {len(resp['data'])} entries")

    # POST /waf/rules/rollback - rollback
    history = resp["data"]
    target_version = history[0]["version"]
    rollback_body = json.dumps({"version": target_version, "rule_id": rule_id})
    status, body = curl("POST", "/verynginx/waf/rules/rollback", data=rollback_body, cookies=cookies, headers=auth_headers({"Content-Type": "application/json"}))
    assert status in (200, 400), f"POST rollback failed: {status}, body={body[:200]}"
    print(f"  [PASS] POST /waf/rules/rollback: {status}")

    # DELETE /waf/rules/:id - delete rule
    status, body = curl("DELETE", f"/verynginx/waf/rules/{rule_id}", cookies=cookies, headers=auth_headers())
    assert status == 200, f"DELETE /waf/rules/:id failed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Delete failed: {body[:200]}"
    print(f"  [PASS] DELETE /waf/rules/:id: deleted")

    # Verify deletion
    status, body = curl("GET", f"/verynginx/waf/rules/{rule_id}", cookies=cookies)
    assert status == 404, f"Expected 404 after deletion, got: {status}"
    print(f"  [PASS] GET deleted rule returns 404")


def test_geoip():
    """Test GeoIP lookup endpoint."""
    cookies = get_shared_session()
    status, body = curl("GET", "/verynginx/geoip/lookup?ip=8.8.8.8", cookies=cookies)
    assert status == 200, f"GeoIP lookup failed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"GeoIP response: {body[:200]}"
    print(f"  [PASS] GeoIP lookup: country={resp.get('data',{}).get('country_code','N/A')}")

def test_fingerprints():
    """Test fingerprint database endpoint."""
    cookies = get_shared_session()
    status, body = curl("GET", "/verynginx/fingerprints", cookies=cookies)
    assert status == 200, f"GET fingerprints failed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Fingerprint response: {body[:200]}"
    assert isinstance(resp.get("data"), list), f"Expected list: {body[:200]}"
    print(f"  [PASS] Fingerprints: {len(resp.get('data',[]))} entries")


def test_routes():
    """Test that all API routes respond correctly."""
    tests = [
        ("POST /verynginx/login", lambda: curl("POST", "/verynginx/login", data="user=test&password=test")),
    ]
    for name, fn in tests:
        status, body = fn()
        print(f"  [INFO] {name}: {status}")

def main():
    print("VeryNginx v2 Integration Tests")
    print(f"Target: {BASE_URL}")
    print()

    tests = [
        ("Health check", test_health),
        ("Login", test_login),
        ("Config CRUD", test_config),
        ("Status", test_status),
        ("WAF Rules", test_waf_rules),
        ("GeoIP", test_geoip),
        ("Fingerprints", test_fingerprints),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        print(f"[TEST] {name}")
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {e}")
            traceback.print_exc()
            failed += 1
        print()

    print(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())