#!/usr/bin/env python3
"""Smoke-test helper: start project services and assert core endpoints/handlers."""
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD_DIR = os.path.join(REPO_ROOT, "build")
PROXY_PORT = 8080
API_PORT = 8000
TIMEOUT_SECONDS = 60


def check_port(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def wait_for_port(port: int, label: str) -> None:
    deadline = time.time() + TIMEOUT_SECONDS
    last = None
    while time.time() < deadline:
        if check_port(port):
            return
        time.sleep(0.5)
    raise SystemExit(f"{label} did not open port {port}")


def start_rust_proxy():
    proxy_bin = os.path.join(BUILD_DIR, "trakshya-proxy")
    if not os.path.exists(proxy_bin):
        raise SystemExit(f"missing {proxy_bin}")
    config = os.path.join(REPO_ROOT, "config", "trakshya.yaml")
    env = os.environ.copy()
    env.update(
        {
            "TRAKSHYA_CONFIG": config,
            "TRAKSHYA_MGMT_API_URL": f"http://127.0.0.1:{API_PORT}",
            "TRAKSHYA_PROXY_PORT": str(PROXY_PORT),
            "TRAKSHYA_UPSTREAM_URL": "http://127.0.0.1:3000",
            "RUST_LOG": "info",
        }
    )
    proc = subprocess.Popen([proxy_bin], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    wait_for_port(PROXY_PORT, "proxy")
    return proc


def start_go_api():
    api_bin = os.path.join(BUILD_DIR, "trakshya-api")
    if not os.path.exists(api_bin):
        raise SystemExit(f"missing {api_bin}")
    env = os.environ.copy()
    env.update(
        {
            "TRAKSHYA_DB_PATH": os.path.join(REPO_ROOT, "build", "trakshya.db"),
            "TRAKSHYA_FRONTEND_DIR": os.path.join(REPO_ROOT, "frontend"),
            "TRAKSHYA_API_PORT": str(API_PORT),
        }
    )
    proc = subprocess.Popen([api_bin], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    wait_for_port(API_PORT, "api")
    return proc


def http_get(url: str) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "trakshya-smoke/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def assert_status(url: str, expected: int, name: str) -> None:
    status = http_get(url)
    if status != expected:
        raise SystemExit(f"{name} failed: {url} -> {status}, expected {expected}")
    print(f"OK {name}: {url} -> {status}")


def main():
    if platform.system() != "Linux":
        print("Smoke tests are intended for Linux; skipping runtime asserts.")
        return 0

    proxy = start_rust_proxy()
    api = start_go_api()
    procs = [proxy, api]

    try:
        assert_status(f"http://127.0.0.1:{API_PORT}/health", 200, "api_health")
        assert_status(f"http://127.0.0.1:{PROXY_PORT}/health", 200, "proxy_health")
        assert_status(f"http://127.0.0.1:{API_PORT}/api/incidents", 200, "api_incidents")
        assert_status(f"http://127.0.0.1:{API_PORT}/api/rules", 200, "api_rules")
        assert_status(f"http://127.0.0.1:{API_PORT}/", 200, "frontend_root")
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    print("Smoke tests passed.")


if __name__ == "__main__":
    sys.exit(main())
