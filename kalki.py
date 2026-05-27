#!/usr/bin/env python3
"""
KALKI — Unified Launcher
Start the full WAF stack locally. No cloud dependency.

Usage:
  python3 kalki.py                        # Full stack: backend + agent + desktop + browser
  python3 kalki.py server                 # Start backend only (headless)
  python3 kalki.py desktop                # Desktop app only (connect to localhost)
  python3 kalki.py desktop --server URL   # Desktop app → remote server
  python3 kalki.py agent                  # Register local machine as an agent
  python3 kalki.py agent start            # Register + start local monitoring
  python3 kalki.py agent stop             # Stop local agent
  python3 kalki.py agent status           # Check if agent is running
  python3 kalki.py stop                   # Stop all KALKI processes
"""

import os
import sys
import time
import signal
import json
import subprocess
import socket
import atexit
import tempfile
import urllib.parse
from pathlib import Path

KALKI_DIR = Path(__file__).resolve().parent
BACKEND_DIR = KALKI_DIR / "backend"
VENV_DIR = KALKI_DIR / ".venv"
PID_FILE = Path(tempfile.gettempdir()) / "kalki-server.pid"
AGENT_PID_FILE = Path(tempfile.gettempdir()) / "kalki-agent.pid"
AGENT_ID_FILE = KALKI_DIR / ".agent-id"
DEFAULT_PORT = 8080
_kalki_procs: list[subprocess.Popen] = []


# ── auto-setup ─────────────────────────────────────────────────────────

def _ensure_venv():
    """Create .venv + install deps if not already set up."""
    venv_python = _find_python()
    if venv_python != sys.executable:
        # Venv exists — check if it can run the backend
        r = subprocess.run(
            [venv_python, "-c", "import uvicorn, fastapi, PIL"],
            capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return True

    print("[KALKI] Setting up virtual environment (one-time) ...")
    python = sys.executable or "python3"

    # Create venv
    if not VENV_DIR.exists():
        r = subprocess.run([python, "-m", "venv", str(VENV_DIR)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[KALKI] Failed to create venv: {r.stderr.strip()}", file=sys.stderr)
            return False

    # Find venv pip (absolute path)
    pip_candidates = [VENV_DIR / "bin" / "pip3", VENV_DIR / "bin" / "pip"]
    pip = str(next((p for p in pip_candidates if p.exists()), pip_candidates[0]).absolute())

    # Install deps
    req = BACKEND_DIR / "requirements.txt"
    print("[KALKI] Installing dependencies (this may take a minute) ...")
    r = subprocess.run(
        [pip, "install", "-r", str(req), "requests", "sseclient-py", "pillow", "--quiet"],
        capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"[KALKI] pip install failed: {r.stderr.strip()[:300]}", file=sys.stderr)
        return False

    print("[KALKI] Setup complete")
    return True


# ── helpers ────────────────────────────────────────────────────────────

def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def _wait_for_server(port: int, timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            import urllib.request
            r = urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2)
            if r.status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def _find_python() -> str:
    """Use .venv interpreter if available, else system python.
    Returns the venv symlink path (not resolved) so venv site-packages are used."""
    for p in [VENV_DIR / "bin" / "python3",
              VENV_DIR / "bin" / "python"]:
        if p.exists():
            return str(p.absolute())
    return sys.executable or "python3"


# ── start server ───────────────────────────────────────────────────────

def start_server(port: int = DEFAULT_PORT, force: bool = False) -> subprocess.Popen | None:
    if not _port_free(port):
        if force:
            print(f"[KALKI] Port {port} in use — force-killing ...")
            subprocess.run(["fuser", "-k", f"{port}/tcp"],
                           capture_output=True, timeout=5)
            time.sleep(1)
        else:
            print(f"[KALKI] Server already running on port {port}")
            return None

    # If there's an old PID file, remove it
    if PID_FILE.exists():
        PID_FILE.unlink()

    env = os.environ.copy()
    env.pop("LD_PRELOAD", None)
    env["GTK_MODULES"] = ""
    env.setdefault("KALKI_PORT", str(port))
    env.setdefault("OTEL_SDK_DISABLED", "true")
    env.setdefault("CORS_ORIGINS", "*")
    env.setdefault("ADMIN_API_KEY", "dev-key-change-me")

    print(f"[KALKI] Starting backend on http://127.0.0.1:{port} ...")
    proc = subprocess.Popen(
        [_find_python(), "-m", "uvicorn", "main:app",
         "--host", "127.0.0.1", "--port", str(port),
         "--log-level", "warning"],
        cwd=str(BACKEND_DIR),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _kalki_procs.append(proc)

    # Write PID file
    PID_FILE.write_text(str(proc.pid))

    if _wait_for_server(port):
        print(f"[KALKI] Backend is live at http://127.0.0.1:{port}")
        return proc
    else:
        print(f"[KALKI] Backend failed to start within timeout", file=sys.stderr)
        proc.terminate()
        return None


# ── start desktop ──────────────────────────────────────────────────────

def start_desktop(server: str = f"http://127.0.0.1:{DEFAULT_PORT}"):
    desktop_py = KALKI_DIR / "kalki-desktop.py"
    if not desktop_py.exists():
        print(f"[KALKI] kalki-desktop.py not found at {desktop_py}", file=sys.stderr)
        return
    print(f"[KALKI] Launching desktop app (server: {server}) ...")
    env = os.environ.copy()
    env.pop("LD_PRELOAD", None)
    env["GTK_MODULES"] = ""
    env["KALKI_SERVER"] = server
    proc = subprocess.Popen(
        [_find_python(), str(desktop_py)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _kalki_procs.append(proc)


# ── open dashboard in browser ─────────────────────────────────────────

def open_browser(port: int = DEFAULT_PORT):
    import webbrowser
    url = f"http://127.0.0.1:{port}"
    print(f"[KALKI] Opening dashboard: {url}")
    webbrowser.open(url)


# ── local agent ─────────────────────────────────────────────────────────

def _get_agent_id() -> str:
    """Read or create a persistent agent ID for this machine."""
    if AGENT_ID_FILE.exists():
        return AGENT_ID_FILE.read_text().strip()
    import uuid
    agent_id = str(uuid.uuid4())[:12]
    AGENT_ID_FILE.write_text(agent_id)
    return agent_id


def _stop_local_agent():
    """Stop the local monitoring agent."""
    if AGENT_PID_FILE.exists():
        try:
            pid = int(AGENT_PID_FILE.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            print(f"[KALKI] Agent stopped (PID {pid})")
        except (ProcessLookupError, ValueError, OSError):
            print("[KALKI] Agent not running")
        AGENT_PID_FILE.unlink(missing_ok=True)


def _register_local_agent(port: int = DEFAULT_PORT) -> str | None:
    """Register this machine as an agent with the local WAF."""
    agent_id = _get_agent_id()
    hostname = socket.gethostname()
    os_info = f"{sys.platform} python={sys.version.split()[0]}"
    ip = "127.0.0.1"
    url = f"http://127.0.0.1:{port}/api/v1/agents/register"
    params = f"?hostname={urllib.parse.quote(hostname)}&os_info={urllib.parse.quote(os_info)}&ip_address={ip}&agent_version=2.0.0"
    try:
        req = urllib.request.Request(url + params, method="POST")
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read())
        print(f"[KALKI] Agent registered: {hostname} ({agent_id})")
        return agent_id
    except Exception as e:
        print(f"[KALKI] Agent registration failed: {e}")
        return None


def _start_local_agent(port: int = DEFAULT_PORT):
    """Start the local monitoring agent as a subprocess."""
    if AGENT_PID_FILE.exists():
        try:
            pid = int(AGENT_PID_FILE.read_text().strip())
            os.kill(pid, 0)
            print(f"[KALKI] Agent already running (PID {pid})")
            return
        except (ProcessLookupError, OSError, ValueError):
            AGENT_PID_FILE.unlink(missing_ok=True)

    agent_py = KALKI_DIR / "agents" / "kalki-agent.py"
    if not agent_py.exists():
        print(f"[KALKI] Agent script not found: {agent_py}", file=sys.stderr)
        return

    agent_id = _get_agent_id()
    server = f"http://127.0.0.1:{port}"
    print(f"[KALKI] Starting local agent (ID: {agent_id}) ...")
    agent_env = os.environ.copy()
    agent_env.pop("LD_PRELOAD", None)
    agent_env["GTK_MODULES"] = ""
    proc = subprocess.Popen(
        [_find_python(), str(agent_py),
         "--server", server,
         "--agent-id", agent_id],
        env=agent_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    AGENT_PID_FILE.write_text(str(proc.pid))
    _kalki_procs.append(proc)
    print(f"[KALKI] Agent running (PID {proc.pid})")


# ── stop ───────────────────────────────────────────────────────────────

_stopped = False

def stop_all():
    global _stopped
    if _stopped:
        return
    _stopped = True
    # Kill children
    for p in _kalki_procs:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass

    # Kill from PID file
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
        except (ProcessLookupError, ValueError, OSError):
            pass
        PID_FILE.unlink(missing_ok=True)

    # Kill agent from PID file
    if AGENT_PID_FILE.exists():
        try:
            pid = int(AGENT_PID_FILE.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.3)
        except (ProcessLookupError, ValueError, OSError):
            pass
        AGENT_PID_FILE.unlink(missing_ok=True)

    # Also kill any lingering uvicorn on our port
    try:
        subprocess.run(["fuser", "-k", f"{DEFAULT_PORT}/tcp"],
                       capture_output=True, timeout=5)
    except Exception:
        pass

    print("[KALKI] Stopped")


# ── CLI ────────────────────────────────────────────────────────────────

def main():
    # Handle agent subcommand before argparse (since it has its own sub-modes)
    if len(sys.argv) > 1 and sys.argv[1] == "agent":
        sub_mode = sys.argv[2] if len(sys.argv) > 2 else "register"
        port = DEFAULT_PORT
        # Check for --port in remaining args
        for i, arg in enumerate(sys.argv):
            if arg == "--port" and i + 1 < len(sys.argv):
                port = int(sys.argv[i + 1])
        if sub_mode == "stop":
            _stop_local_agent()
            return
        elif sub_mode == "status":
            if AGENT_PID_FILE.exists():
                try:
                    pid = int(AGENT_PID_FILE.read_text().strip())
                    os.kill(pid, 0)
                    print(f"[KALKI] Agent running (PID {pid})")
                except (ProcessLookupError, OSError, ValueError):
                    print("[KALKI] Agent not running (stale PID)")
            else:
                print("[KALKI] Agent not running")
            return

        # register/start need venv + server
        if not _ensure_venv():
            print("[KALKI] Setup failed — install deps manually: pip install -r backend/requirements.txt")
            sys.exit(1)
        if not _wait_for_server(port):
            print(f"[KALKI] Server not ready on port {port} — start it first: python3 kalki.py server")
            return
        _register_local_agent(port)
        if sub_mode == "start":
            _start_local_agent(port)
        return

    import argparse
    parser = argparse.ArgumentParser(description="KALKI — Local WAF Stack")
    parser.add_argument("mode", nargs="?",
                        choices=["start", "server", "desktop", "stop"],
                        default="start",
                        help="start (default): backend + desktop + browser")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Port (default: {DEFAULT_PORT})")
    parser.add_argument("--server", type=str,
                        help="Server URL for desktop mode")
    parser.add_argument("--no-browser", action="store_true",
                        help="Don't open browser in start mode")
    parser.add_argument("--force", "-f", action="store_true",
                        help="Kill existing process on port and restart")
    args = parser.parse_args()

    if args.mode == "stop":
        stop_all()
        return

    atexit.register(stop_all)
    signal.signal(signal.SIGINT, lambda s, f: (stop_all(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda s, f: (stop_all(), sys.exit(0)))

    if args.mode in ("server", "start"):
        if not _ensure_venv():
            print("[KALKI] Setup failed — install deps manually: pip install -r backend/requirements.txt")
            sys.exit(1)

    if args.mode == "server":
        proc = start_server(args.port, force=args.force)
        if proc:
            try:
                proc.wait()
            except KeyboardInterrupt:
                stop_all()
        return

    if args.mode == "desktop":
        server_url = args.server or os.environ.get("KALKI_SERVER",
                          f"http://127.0.0.1:{args.port}")
        start_desktop(server_url)
        # Keep alive
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            stop_all()
        return

    # ── "start" mode ──
    proc = start_server(args.port, force=args.force)
    if not proc:
        # Server might already be running
        pass

    # Register + start local agent
    _register_local_agent(args.port)
    _start_local_agent(args.port)

    if not args.no_browser:
        open_browser(args.port)

    # Launch desktop app in background (no import check — subprocess handles it)
    start_desktop(f"http://127.0.0.1:{args.port}")

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop_all()


if __name__ == "__main__":
    main()
