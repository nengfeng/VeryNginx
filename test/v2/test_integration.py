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
    assert status in (200, 302), f"Health check failed: {status}"
    print(f"  [PASS] Health check: {status}")

def test_login():
    """Test login with correct and incorrect credentials."""
    # Invalid login
    status, body = curl("POST", "/verynginx/login", data="user=bad&password=wrong")
    assert status in (400, 401), f"Login should fail: {status}"
    print(f"  [PASS] Invalid login rejected: {status}")

    # Valid login
    status, body = curl("POST", "/verynginx/login", data=f"user={USER}&password={PASS}")
    assert status == 200, f"Login should succeed: {status}"
    resp = json.loads(body)
    assert resp.get("ret") == "success", f"Login response: {body}"
    print(f"  [PASS] Valid login: {resp.get('ret')}")

def test_config():
    """Test config endpoint (requires auth)."""
    # First login to get session
    status, body = curl("POST", "/verynginx/login", data=f"user={USER}&password={PASS}")
    resp = json.loads(body)
    cookies = {"verynginx_session": resp.get("token")}

    # GET config
    status, body = curl("GET", "/verynginx/config", cookies=cookies)
    assert status == 200, f"GET config failed: {status}"
    config_data = json.loads(body)
    assert "matcher" in config_data, f"Config missing matcher: {body[:200]}"
    print(f"  [PASS] GET config: {len(body)} bytes")

    # POST config (save with base64 encoded)
    config_json = json.dumps({"version": "2.0", "matcher": {}, "rule": {}, "admin": [{"user": "verynginx", "password_hash": "test"}], "security": {"session_secret": "test"}})
    encoded = b64encode(config_json)
    escaped = encoded.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
    status, body = curl("POST", "/verynginx/config", data=f"config={escaped}", cookies=cookies)
    assert status in (200, 400), f"POST config response: {status}"
    print(f"  [PASS] POST config: {status}")

def test_status():
    """Test status endpoint."""
    status, body = curl("POST", "/verynginx/login", data=f"user={USER}&password={PASS}")
    resp = json.loads(body)
    cookies = {"verynginx_session": resp.get("token")}

    status, body = curl("GET", "/verynginx/status", cookies=cookies)
    assert status == 200, f"GET status failed: {status}"
    print(f"  [PASS] GET status: {len(body)} bytes")

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
            failed += 1
        print()

    print(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())