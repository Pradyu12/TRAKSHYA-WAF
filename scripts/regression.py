#!/usr/bin/env python3
"""Local regression checks for TRAKSHYA-WAF VAPT + WAF rule detection."""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
import urllib.error


BASE = os.environ.get("TRAKSHYA_REGRESSION_BASE", "http://127.0.0.1:8000")
PROXY_BASE = os.environ.get("TRAKSHYA_PROXY_BASE", "http://127.0.0.1:8080")


def check(name: str, condition: bool, detail: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))
    return condition


def request(url: str, *, path: str = "", method: str = "GET", body: bytes | None = None, headers: dict[str, str] | None = None, host: str | None = None):
    target = url.rstrip("/") + path
    req = urllib.request.Request(target, method=method, data=body)
    req.add_header("User-Agent", "trakshya-regression/1.0")
    req.add_header("Accept", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if host:
        req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = resp.read().decode("utf-8", "ignore")
            return resp.status, resp.headers, payload
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", "ignore")
        return exc.code, exc.headers, payload
    except Exception as exc:
        return 0, {}, str(exc)


def rule_checks() -> bool:
    print("\n== WAF rule regex checks ==")
    rules = [
        ("SQLI-001", re.compile(r"(?i)\bunion\b.*\bselect\b|\bdrop\b.*\btable\b"), "UNION SELECT", True),
        ("XSS-001", re.compile(r"(?i)<script|javascript:|onerror=|onload="), "<script>", True),
        ("TRAV-001", re.compile(r"(?i)\.\./|%2e%2e"), "../etc/passwd", True),
        ("CMDI-001", re.compile(r"(?i);\s*(cat|ls|rm|sh|bash)|`.*`|\$\("), "; ls", True),
        ("RFI-001", re.compile(r"(?i)include=|require=|file=.*http"), "file=http://evil", True),
        ("LFI-001", re.compile(r"(?i)\.\./etc/passwd|/proc/self"), "../../etc/passwd", True),
        ("SCANNER-001", re.compile(r"(?i)wp-admin|phpmyadmin|/manager"), "/wp-admin", True),
        ("BRUTE-001", re.compile(r"(?i)/api/auth/login.*POST"), "/api/auth/login", True),
    ]
    ok = True
    for rule_id, pattern, payload, expected in rules:
        matched = bool(pattern.search(payload))
        ok &= check(rule_id, matched == expected, f"payload={payload!r} matched={matched}")
    return ok


def mock_server_checks() -> bool:
    print("\n== Mock server endpoint checks ==")
    ok = True
    status, _, body = request(BASE, path="/health")
    ok &= check("mock_health", status == 200, f"status={status}")

    status, _, body = request(BASE, path="/api/dashboard/stats")
    ok &= check("mock_dashboard_stats_json", status == 200 and "total_requests" in body, f"status={status}")

    status, _, body = request(BASE, path="/api/incidents")
    ok &= check("mock_incidents_json", status == 200 and "attack_blocked" in body, f"status={status}")

    status, _, body = request(BASE, path="/api/siem/stats")
    ok &= check("mock_siem_stats_json", status == 200 and "by_severity" in body, f"status={status}")

    status, _, body = request(BASE, path="/api/vapt/stats")
    ok &= check("mock_vapt_stats_json", status == 200 and "TotalFindings" in body, f"status={status}")

    status, _, body = request(BASE, path="/api/rules")
    ok &= check("mock_rules_json", status == 200 and "SQLI-001" in body, f"status={status}")

    status, _, body = request(BASE, path="/api/mitigation-posture")
    ok &= check("mock_posture_alias", status == 200 and "monitor" in body, f"status={status}")

    return ok


def waf_proxy_checks() -> bool:
    print("\n== WAF proxy behavior checks ==")
    ok = True

    malicious_queries = [
        ("sql_injection", "/search?q=UNION+SELECT+1,2,3"),
        ("xss", "/page?payload=<script>alert(1)</script>"),
        ("path_traversal", "/files?name=../../etc/passwd"),
        ("command_injection", "/debug?cmd=;ls+-la"),
    ]
    blocked_responses = []
    for attack, path in malicious_queries:
        status, headers, body = request(PROXY_BASE, path=path)
        blocked = status == 403 or body.lower().count("blocked") > 0 or headers.get("x-trakshya-blocked") == "true"
        blocked_responses.append((attack, blocked, status))
        ok &= check(f"proxy_block_{attack}", blocked, f"status={status} path={path}")
    return ok


def main() -> int:
    results = [rule_checks(), mock_server_checks(), waf_proxy_checks()]
    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"\n== Summary: {passed}/{total} suites passed ==")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
