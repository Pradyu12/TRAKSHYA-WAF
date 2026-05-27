#!/usr/bin/env python3
"""
KALKI Desktop — Live SIEM/XDR Monitor
Native desktop app. Real-time SSE + alert polling + system tray.
Package: pyinstaller --onefile --windowed --icon=frontend/kalki_waf_logo.png kalki-desktop.py
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time
import warnings
import socket
import math
import random
from datetime import UTC, datetime

# Suppress noisy GTK/GLib/Datadog preload warnings at startup
os.environ.setdefault("GTK_MODULES", "")
os.environ.pop("LD_PRELOAD", None)
warnings.filterwarnings("ignore", category=UserWarning)

# ── Dependencies ──────────────────────────────────────────────────────
try:
    import requests
    import sseclient
except ImportError:
    print("Install: pip install requests sseclient-py")
    sys.exit(1)

try:
    import tkinter as tk
    from tkinter import ttk
except ImportError:
    print("tkinter not available. Linux: sudo apt install python3-tk")
    sys.exit(1)

try:
    from PIL import Image, ImageTk
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False

# ── Config ────────────────────────────────────────────────────────────
SERVER = os.environ.get("KALKI_SERVER", "http://127.0.0.1:8080")
POLL_INTERVAL = 3
SSE_TIMEOUT = 45
MAX_RECONNECT_DELAY = 30

# Parse --server CLI flag (overrides env / default)
if "--server" in sys.argv:
    idx = sys.argv.index("--server")
    if idx + 1 < len(sys.argv):
        SERVER = sys.argv[idx + 1]

_BASE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
_LOGO_PATH = os.environ.get("KALKI_LOGO", "")
if not _LOGO_PATH:
    for p in [
        os.path.join(_BASE_DIR, "kalki_waf_logo.png"),
        os.path.join(_BASE_DIR, "frontend", "kalki_waf_logo.png"),
    ]:
        if os.path.isfile(p):
            _LOGO_PATH = p
            break


# ── App ───────────────────────────────────────────────────────────────
class KalkiDesktop:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("KALKI SIEM/XDR — Live")
        self.root.geometry("860x540")
        self.root.configure(bg="#0d0d12")
        self.root.minsize(640, 400)

        self._running = True
        self._last_alert_id = 0
        self._connected = False
        self._cmd_queue: queue.Queue = queue.Queue()

        self._load_logo()
        self._build_ui()
        self._setup_tray()

        self._start_threads()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── Logo loading ──────────────────────────────────────────────────
    def _load_logo(self):
        self._logo_img = None
        self._tray_img = None
        if _HAS_PIL and _LOGO_PATH:
            try:
                img = Image.open(_LOGO_PATH)
                self._tray_img = ImageTk.PhotoImage(img.resize((16, 16), Image.LANCZOS))
                logo = img.resize((26, 26), Image.LANCZOS)
                self._logo_img = ImageTk.PhotoImage(logo)
                icon = ImageTk.PhotoImage(img.resize((32, 32), Image.LANCZOS))
                self.root.iconphoto(True, icon)
            except Exception:
                pass

    # ── UI Build ──────────────────────────────────────────────────────
    def _build_ui(self):
        # Top bar
        top = tk.Frame(self.root, bg="#0d0d12", height=40)
        top.pack(fill="x", padx=12, pady=(8, 2))

        logo_frame = tk.Frame(top, bg="#0d0d12")
        logo_frame.pack(side="left")
        if self._logo_img:
            tk.Label(logo_frame, image=self._logo_img, bg="#0d0d12").pack(side="left")
            tk.Label(logo_frame, text="  KALKI", font=("Consolas", 15, "bold"),
                     fg="#00dddd", bg="#0d0d12").pack(side="left")
        else:
            tk.Label(logo_frame, text="KALKI", font=("Consolas", 15, "bold"),
                     fg="#00dddd", bg="#0d0d12").pack(side="left")

        is_remote = "kalki-waf.onrender" in SERVER or not SERVER.startswith("http://127")
        if is_remote:
            tk.Label(top, text="☁ remote", font=("Consolas", 7),
                     fg="#fe00fe", bg="#0d0d12").pack(side="left", padx=(8, 0))
        else:
            tk.Label(top, text="◈ local", font=("Consolas", 7),
                     fg="#00dddd", bg="#0d0d12").pack(side="left", padx=(8, 0))

        self.status_dot = tk.Label(top, text="●", font=("Consolas", 9),
                                   fg="#4edea3", bg="#0d0d12")
        self.status_dot.pack(side="left", padx=(14, 2))
        self.status_lbl = tk.Label(top, text="LIVE", font=("Consolas", 8),
                                   fg="#4edea3", bg="#0d0d12")
        self.status_lbl.pack(side="left")

        self.server_lbl = tk.Label(top, text=SERVER.replace("https://", ""),
                                   font=("Consolas", 8), fg="#3a3a46", bg="#0d0d12")
        self.server_lbl.pack(side="left", padx=(12, 0))

        self.clock_lbl = tk.Label(top, text="", font=("Consolas", 8),
                                  fg="#3a3a46", bg="#0d0d12")
        self.clock_lbl.pack(side="right")

        # ── Metrics strip ──
        self.metrics = {}
        mf = tk.Frame(self.root, bg="#0d0d12")
        mf.pack(fill="x", padx=12, pady=4)
        for label in ["Threats", "Alerts", "Agents", "CPU", "Mem", "Req/s"]:
            f = tk.Frame(mf, bg="#14141e", highlightbackground="#1c1c28",
                         highlightthickness=1, padx=10, pady=5)
            f.pack(side="left", padx=3, fill="x", expand=True)
            tk.Label(f, text=label, font=("Consolas", 7), fg="#6a6a78",
                     bg="#14141e").pack()
            lbl = tk.Label(f, text="—", font=("Consolas", 14, "bold"),
                           fg="#e0dfe6", bg="#14141e")
            lbl.pack()
            self.metrics[label] = lbl

        # ── Main panels ──
        pw = tk.PanedWindow(self.root, bg="#0d0d12", sashwidth=4, sashrelief="flat")
        pw.pack(fill="both", expand=True, padx=12, pady=4)

        # Left: Alerts
        left = tk.Frame(pw, bg="#0d0d12")
        pw.add(left, width=420)
        tk.Label(left, text="ALERTS", font=("Consolas", 8, "bold"),
                 fg="#6a6a78", bg="#0d0d12").pack(anchor="w", pady=(0, 3))

        alert_frame = tk.Frame(left, bg="#0e0e14", highlightbackground="#1c1c28",
                               highlightthickness=1)
        alert_frame.pack(fill="both", expand=True)
        self.alerts_box = tk.Text(alert_frame, font=("Consolas", 9), bg="#0e0e14",
                                   fg="#e0dfe6", insertbackground="#e0dfe6",
                                   relief="flat", state="disabled", padx=6, pady=4)
        self.alerts_box.pack(fill="both", expand=True)

        # Right: Local Agent & Radar
        right = tk.Frame(pw, bg="#0d0d12")
        pw.add(right, width=420)
        tk.Label(right, text="LOCAL AGENT", font=("Consolas", 8, "bold"),
                 fg="#6a6a78", bg="#0d0d12").pack(anchor="w", pady=(0, 3))

        # Local Agent Info
        agent_info_frame = tk.Frame(right, bg="#0e0e14", highlightbackground="#1c1c28",
                                    highlightthickness=1)
        agent_info_frame.pack(fill="x", padx=6, pady=6)
        self.agent_status_lbl = tk.Label(agent_info_frame, text="● Active", font=("Consolas", 10, "bold"),
                                         fg="#4edea3", bg="#0e0e14")
        self.agent_status_lbl.pack(side="left")
        self.agent_hostname_lbl = tk.Label(agent_info_frame, text="Hostname: ?", font=("Consolas", 9),
                                           fg="#e0dfe6", bg="#0e0e14")
        self.agent_hostname_lbl.pack(side="left", padx=(10, 0))
        self.agent_ip_lbl = tk.Label(agent_info_frame, text="IP: ?", font=("Consolas", 9),
                                     fg="#e0dfe6", bg="#0e0e14")
        self.agent_ip_lbl.pack(side="left", padx=(10, 0))
        self.agent_hb_lbl = tk.Label(agent_info_frame, text="HB: ?", font=("Consolas", 9),
                                     fg="#e0dfe6", bg="#0e0e14")
        self.agent_hb_lbl.pack(side="left", padx=(10, 0))

        # Global Threat Radar
        radar_frame = tk.Frame(right, bg="#0d0d12")
        radar_frame.pack(fill="both", expand=True, padx=6, pady=(6, 0))
        self.radar_canvas = tk.Canvas(radar_frame, bg="#000000", highlightthickness=0)
        self.radar_canvas.pack(fill="both", expand=True)
        self._draw_radar()
        self._start_radar_sweep()

        # ── Bottom bar ──
        bottom = tk.Frame(self.root, bg="#0d0d12", height=26)
        bottom.pack(fill="x", padx=12, pady=(0, 6))

        self.conn_lbl = tk.Label(bottom, text="● SSE: connected", font=("Consolas", 8),
                                 fg="#4edea3", bg="#0d0d12")
        self.conn_lbl.pack(side="left")
        self.uptime_lbl = tk.Label(bottom, text="", font=("Consolas", 8),
                                   fg="#3a3a46", bg="#0d0d12")
        self.uptime_lbl.pack(side="right")

        self._start_time = time.time()
        self._clock()

    # ── System tray ──────────────────────────────────────────────────
    def _setup_tray(self):
        self._tray_icon = None
        self._tray_menu = None
        try:
            import pystray
            from pystray import MenuItem as Item
            menu = (Item("Show", self._tray_show, default=True),
                    Item("Quit", self._tray_quit))
            icon_img = None
            if _HAS_PIL and _LOGO_PATH:
                icon_img = Image.open(_LOGO_PATH).resize((64, 64), Image.LANCZOS)
            self._tray_icon = pystray.Icon("kalki", icon_img or Image.new("RGB", (64, 64), "#0d0d12"),
                                           "KALKI SIEM/XDR", menu)
            self._tray_thread = threading.Thread(target=self._tray_icon.run, daemon=True)
            self._tray_thread.start()
        except Exception:
            pass  # Tray unavailable (no DE, no DISPLAY, etc.)

    def _tray_show(self):
        self.root.deiconify()
        self.root.lift()

    def _tray_quit(self):
        self._running = False
        if self._tray_icon:
            self._tray_icon.stop()
        self.root.after(0, self.root.destroy)

    # ── Clock ─────────────────────────────────────────────────────────
    def _clock(self):
        if not self._running:
            return
        now = datetime.now(UTC)
        self.clock_lbl.configure(text=now.strftime("%H:%M:%S UTC"))
        uptime = int(time.time() - self._start_time)
        self.uptime_lbl.configure(text=f"uptime: {uptime // 3600}h{(uptime % 3600) // 60}m")
        self.root.after(1000, self._clock)

    # ── Threads ──────────────────────────────────────────────────────
    def _start_threads(self):
        def worker(target):
            while self._running:
                try:
                    target()
                except Exception as e:
                    self._enqueue(lambda e=e: self._status(f"error", str(e)))
                    time.sleep(3)

        threading.Thread(target=worker, args=(self._sse_loop,), daemon=True).start()
        threading.Thread(target=worker, args=(self._poll_loop,), daemon=True).start()
        threading.Thread(target=worker, args=(self._full_refresh_loop,), daemon=True).start()
        self._process_queue()

    def _enqueue(self, fn):
        self._cmd_queue.put(fn)

    def _process_queue(self):
        try:
            fn = self._cmd_queue.get_nowait()
            fn()
        except queue.Empty:
            pass
        except Exception:
            pass
        if self._running:
            self.root.after(50, self._process_queue)

    # ── SSE ──────────────────────────────────────────────────────────
    def _sse_loop(self):
        delay = 1
        while self._running:
            try:
                with requests.get(f"{SERVER}/api/v1/stream", stream=True,
                                  timeout=SSE_TIMEOUT) as resp:
                    if resp.status_code != 200:
                        raise ConnectionError(f"HTTP {resp.status_code}")
                    client = sseclient.SSEClient(resp)
                    self._connected = True
                    delay = 1
                    self._enqueue(lambda: self._set_status("connected"))
                    for event in client.events():
                        if not self._running:
                            return
                        d = json.loads(event.data)
                        self._enqueue(lambda d=d: self._on_sse(d))
            except Exception as e:
                self._connected = False
                self._enqueue(lambda e=e: self._set_status(f"reconnecting ({e})"))
                time.sleep(delay)
                delay = min(delay * 2, MAX_RECONNECT_DELAY)

    def _on_sse(self, d):
        m = d.get("metrics", {})
        if m:
            self.metrics["CPU"].configure(text=f'{m.get("cpu_percent", 0):.1f}%')
            self.metrics["Mem"].configure(text=f'{m.get("memory_mb", 0):.0f} MB')
            self.metrics["Req/s"].configure(text=f'{m.get("requests_per_second", 0):.1f}')

    # ── Alert polling ────────────────────────────────────────────────
    def _poll_loop(self):
        while self._running:
            try:
                r = requests.get(f"{SERVER}/api/v1/siem/alerts?limit=20", timeout=10)
                if r.status_code == 200:
                    alerts = r.json()
                    if isinstance(alerts, list):
                        for a in reversed(alerts):
                            aid = a.get("id", 0)
                            if aid > self._last_alert_id:
                                self._last_alert_id = aid
                                sev = (a.get("severity", "info") or "info").lower()
                                desc = (a.get("description")
                                        or a.get("rule_name")
                                        or a.get("source")
                                        or "?")[:80]
                                rule = a.get("rule_name", "")
                                self._enqueue(lambda sev=sev, desc=desc, rule=rule:
                                              self._on_alert(sev, desc, rule))
            except Exception:
                pass
            time.sleep(POLL_INTERVAL)

    def _on_alert(self, sev, desc, rule):
        colors = {"critical": "#ff4d6d", "high": "#fe00fe",
                  "medium": "#ffb95f", "low": "#4edea3", "info": "#4a4a56"}
        c = colors.get(sev, "#4a4a56")
        tag = f"alert-{sev}-{time.time_ns()}"
        self.alerts_box.configure(state="normal")
        self.alerts_box.insert("1.0", f"[{sev.upper():8}] {desc}\n", tag)
        self.alerts_box.tag_configure(tag, foreground=c)
        lines = self.alerts_box.get("1.0", "end-1c").split("\n")
        if len(lines) > 200:
            self.alerts_box.delete("end-2l", "end")
        self.alerts_box.configure(state="disabled")
        self.metrics["Alerts"].configure(
            text=str(int(self.metrics["Alerts"].cget("text") or 0) + 1))
        if sev in ("critical", "high"):
            self._notify(f"[{sev.upper()}] {rule}", desc)

    # ── Full refresh ─────────────────────────────────────────────────
    def _full_refresh_loop(self):
        while self._running:
            try:
                r = requests.get(f"{SERVER}/api/v1/siem/dashboard", timeout=10)
                if r.status_code == 200:
                    d = r.json()
                    self._enqueue(lambda d=d: self._on_refresh(d))
            except Exception:
                pass
            time.sleep(15)

    def _on_refresh(self, d):
        ls = d.get("live_stats", {})
        siem = d.get("siem", {})
        agents = d.get("agents", {})
        self.metrics["Threats"].configure(text=str(siem.get("total", 0)))
        self.metrics["Agents"].configure(
            text=f"{agents.get('online', 0)}/{agents.get('total', 0)}")
        if ls:
            self.metrics["CPU"].configure(text=f'{ls.get("cpu_percent", 0):.1f}%')
            self.metrics["Mem"].configure(text=f'{ls.get("memory_mb", 0):.0f} MB')
            self.metrics["Req/s"].configure(text=f'{ls.get("requests_per_second", 0):.1f}')
        
        # Update local agent info
        alist = agents.get("list", [])
        local_hostname = socket.gethostname()
        local_agent = None
        for a in alist:
            if a.get("hostname") == local_hostname:
                local_agent = a
                break
        
        if local_agent:
            st = local_agent.get("status", "inactive")
            self.agent_status_lbl.configure(text="● Active" if st == "active" else "○ Inactive",
                                          fg="#4edea3" if st == "active" else "#ff4d6d")
            self.agent_hostname_lbl.configure(text=f"Hostname: {local_agent.get('hostname', '?')}")
            self.agent_ip_lbl.configure(text=f"IP: {local_agent.get('ip_address', '?')}")
            hb = local_agent.get("last_heartbeat", "")
            if hb:
                hb_short = hb[:19] if len(hb) > 19 else hb
                self.agent_hb_lbl.configure(text=f"HB: {hb_short}")
            else:
                self.agent_hb_lbl.configure(text="HB: Never")

    # ── Status bar ───────────────────────────────────────────────────
    def _set_status(self, msg):
        if "connected" in msg:
            self.conn_lbl.configure(text="● SSE: connected", fg="#4edea3")
            self.status_dot.configure(fg="#4edea3")
            self.status_lbl.configure(text="LIVE", fg="#4edea3")
        else:
            self.conn_lbl.configure(text=f"○ SSE: {msg}", fg="#ff4d6d")
            self.status_dot.configure(fg="#ff4d6d")
            self.status_lbl.configure(text="DISCONNECTED", fg="#ff4d6d")

    def _status(self, prefix, msg):
        self.conn_lbl.configure(text=f"○ {prefix}: {msg[:40]}", fg="#ffb95f")

    # ── OS Notifications ─────────────────────────────────────────────
    def _notify(self, title, message):
        try:
            if sys.platform == "linux":
                subprocess.Popen(["notify-send", title, message],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys.platform == "darwin":
                subprocess.Popen(["osascript", "-e",
                                  f'display notification "{message}" with title "{title}"'],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys.platform == "win32":
                from plyer import notification
                notification.notify(title=title, message=message, timeout=5)
        except Exception:
            pass

        # ── Radar methods ────────────────────────────────────────────────
        def _draw_radar(self):
            self.radar_canvas.delete("all")
            width = self.radar_canvas.winfo_width()
            height = self.radar_canvas.winfo_height()
            if width <= 1 or height <= 1:
                # Canvas not yet sized, defer drawing
                self.radar_canvas.after(100, self._draw_radar)
                return
            cx, cy = width // 2, height // 2
            radius = min(width, height) // 2 - 10
            # Outer glow (multiple cyan circles)
            for i in range(3):
                r = radius - i * 5
                alpha = 100 - i * 30
                color = f'#00{alpha:02x}{alpha:02x}'  # cyan with alpha (tkinter doesn't support alpha, we'll simulate with lighter blue)
                # Since tkinter doesn't support alpha, we'll use solid cyan and rely on stipple or just color
                # We'll use a stipple effect by drawing dashed? Not supported on oval. We'll just use multiple outlines.
                self.radar_canvas.create_oval(cx - r, cy - r, cx + r, cy + r, outline="#00ffff", width=1)
            # Inner grid (simple lines)
            for angle in range(0, 360, 30):
                rad = math.radians(angle)
                x1 = cx + radius * math.cos(rad)
                y1 = cy + radius * math.sin(rad)
                x2 = cx - radius * math.cos(rad)
                y2 = cy - radius * math.sin(rad)
                self.radar_canvas.create_line(x1, y1, x2, y2, fill="#004040", width=1)
            for r in [radius * 0.25, radius * 0.5, radius * 0.75]:
                self.radar_canvas.create_oval(cx - r, cy - r, cx + r, cy + r, outline="#004040", width=1)
            # Sweep line (will be updated by _start_radar_sweep)
            self.sweep_line = self.radar_canvas.create_line(cx, cy, cx, cy - radius, fill="#00ff00", width=2)
            # Pulse dots (representing threats) - we'll generate some random dots based on agent data
            self.threat_dots = []
            # We'll get agent data from the server? For now, simulate with random dots.
            # In future, we could pull from the server's agents list and map to angles.
            # For demo, we'll just add a few random dots.
            self._update_threat_dots()

        def _update_threat_dots(self):
            # Clear previous threat dots
            for dot in self.threat_dots:
                self.radar_canvas.delete(dot)
            self.threat_dots.clear()
            # Get local agent info? We'll just add a few random dots for demo.
            # In a real implementation, we would fetch agents from the server and map them to angles.
            # For now, we'll add 3-5 random dots.
            import random
            width = self.radar_canvas.winfo_width()
            height = self.radar_canvas.winfo_height()
            if width <= 1 or height <= 1:
                self.radar_canvas.after(100, self._update_threat_dots)
                return
            cx, cy = width // 2, height // 2
            radius = min(width, height) // 2 - 10
            num_dots = random.randint(2, 5)
            for _ in range(num_dots):
                angle = random.uniform(0, 2 * math.pi)
                r = random.uniform(0.2, 0.8) * radius
                x = cx + r * math.cos(angle)
                y = cy + r * math.sin(angle)
                dot = self.radar_canvas.create_oval(x-3, y-3, x+3, y+3, fill="#ff00ff", outline="")
                self.threat_dots.append(dot)
            # Schedule next update
            self.radar_canvas.after(2000, self._update_threat_dots)

        def _start_radar_sweep(self):
            self.sweep_angle = 0
            self._animate_sweep()

        def _animate_sweep(self):
            # Update sweep line angle
            self.sweep_angle = (self.sweep_angle + 2) % 360
            rad = math.radians(self.sweep_angle)
            width = self.radar_canvas.winfo_width()
            height = self.radar_canvas.winfo_height()
            if width <= 1 or height <= 1:
                self.radar_canvas.after(50, self._animate_sweep)
                return
            cx, cy = width // 2, height // 2
            radius = min(width, height) // 2 - 10
            x = cx + radius * math.cos(rad)
            y = cy + radius * math.sin(rad)
            self.radar_canvas.coords(self.sweep_line, cx, cy, x, y)
            self.radar_canvas.after(50, self._animate_sweep)

        # ── Window close → tray ──────────────────────────────────────────
        def _on_close(self):
        if self._tray_icon:
            self.root.withdraw()
        else:
            self._running = False
            self.root.destroy()

    # ── Run ──────────────────────────────────────────────────────────
    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()


if __name__ == "__main__":
    print("KALKI Desktop — Live SIEM/XDR Monitor")
    print(f"Server: {SERVER}")
    print("Usage: python3 kalki-desktop.py [--server URL]")
    print("Close window → minimizes to system tray")
    print()
    KalkiDesktop().run()
