#!/usr/bin/env python3
"""KALKI Desktop — native live monitoring app. No browser needed."""

import json
import os
import sys
import threading
import time
from datetime import UTC, datetime

try:
    import requests
    import sseclient
except ImportError:
    print("Run: pip install requests sseclient-py")
    sys.exit(1)

try:
    import tkinter as tk
    from tkinter import ttk
except ImportError:
    print("tkinter not available. On Linux: sudo apt install python3-tk")
    sys.exit(1)

SERVER = os.environ.get("KALKI_SERVER", "https://kalki-waf.onrender.com")

class KalkiDesktop:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("KALKI SIEM/XDR — Live")
        self.root.geometry("800x500")
        self.root.configure(bg="#0d0d12")
        self.root.resizable(True, True)

        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        style = ttk.Style()
        style.theme_use("clam")

        # ─── Top Bar ───
        top = tk.Frame(self.root, bg="#0d0d12", height=40)
        top.pack(fill="x", padx=10, pady=(8,2))

        tk.Label(top, text="KALKI", font=("Consolas", 16, "bold"),
                 fg="#00dddd", bg="#0d0d12").pack(side="left")

        self.status_lbl = tk.Label(top, text="● LIVE", font=("Consolas", 9),
                                   fg="#4edea3", bg="#0d0d12")
        self.status_lbl.pack(side="left", padx=(12,0))

        self.clock_lbl = tk.Label(top, text="", font=("Consolas", 9),
                                  fg="#3a3a46", bg="#0d0d12")
        self.clock_lbl.pack(side="right")

        # ─── Metrics Strip ───
        metrics_frame = tk.Frame(self.root, bg="#0d0d12")
        metrics_frame.pack(fill="x", padx=10, pady=4)

        self.metrics = {}
        for label in ["Threats", "Alerts", "Agents", "CPU", "Mem", "Req/s"]:
            f = tk.Frame(metrics_frame, bg="#14141e", highlightbackground="#1c1c28",
                         highlightthickness=1, padx=10, pady=6)
            f.pack(side="left", padx=3, fill="x", expand=True)
            tk.Label(f, text=label, font=("Consolas", 8), fg="#6a6a78",
                     bg="#14141e").pack()
            lbl = tk.Label(f, text="—", font=("Consolas", 14, "bold"),
                           fg="#e0dfe6", bg="#14141e")
            lbl.pack()
            self.metrics[label] = lbl

        # ─── Main Content ───
        main_frame = tk.Frame(self.root, bg="#0d0d12")
        main_frame.pack(fill="both", expand=True, padx=10, pady=4)

        # Left: Alerts
        left_frame = tk.Frame(main_frame, bg="#0d0d12")
        left_frame.pack(side="left", fill="both", expand=True, padx=(0,4))

        tk.Label(left_frame, text="LAST ALERTS", font=("Consolas", 8, "bold"),
                 fg="#6a6a78", bg="#0d0d12").pack(anchor="w")

        self.alerts_box = tk.Text(left_frame, font=("Consolas", 9), bg="#0e0e14",
                                   fg="#e0dfe6", insertbackground="#e0dfe6",
                                   relief="flat", height=18, state="disabled")
        self.alerts_box.pack(fill="both", expand=True)

        # Right: Agents
        right_frame = tk.Frame(main_frame, bg="#0d0d12")
        right_frame.pack(side="right", fill="both", expand=True, padx=(4,0))

        tk.Label(right_frame, text="AGENTS", font=("Consolas", 8, "bold"),
                 fg="#6a6a78", bg="#0d0d12").pack(anchor="w")

        self.agents_box = tk.Text(right_frame, font=("Consolas", 9), bg="#0e0e14",
                                   fg="#e0dfe6", insertbackground="#e0dfe6",
                                   relief="flat", height=18, state="disabled")
        self.agents_box.pack(fill="both", expand=True)

        # ─── Bottom Bar ───
        bottom = tk.Frame(self.root, bg="#0d0d12", height=28)
        bottom.pack(fill="x", padx=10, pady=(0,6))

        tk.Label(bottom, text=f"Server: {SERVER}", font=("Consolas", 8),
                 fg="#3a3a46", bg="#0d0d12").pack(side="left")
        self.sse_lbl = tk.Label(bottom, text="SSE: connected", font=("Consolas", 8),
                                fg="#4edea3", bg="#0d0d12")
        self.sse_lbl.pack(side="right")

        self._running = True
        self._alert_count = 0

    def log(self, msg, tag=""):
        self.root.after(0, lambda: self._append_text(self.alerts_box, msg, tag))

    def _append_text(self, box, text, tag=""):
        try:
            box.configure(state="normal")
            box.insert("1.0", text + "\n")
            if tag:
                box.tag_add(tag, "1.0", "1.end")
            # Keep only last 100 lines
            lines = box.get("1.0", "end-1c").split("\n")
            if len(lines) > 100:
                box.delete("end-2l", "end")
            box.configure(state="disabled")
        except Exception:
            pass

    def update_clock(self):
        now = datetime.now(UTC).strftime("%H:%M:%S UTC")
        self.clock_lbl.configure(text=now)
        if self._running:
            self.root.after(1000, self.update_clock)

    def fetch_initial(self):
        try:
            dash = requests.get(f"{SERVER}/api/v1/siem/dashboard", timeout=10).json()
            self._update_metrics(dash)

            agents = dash.get("agents", {})
            agent_list = agents.get("list", [])
            self.root.after(0, lambda: self._render_agents(agent_list))
        except Exception as e:
            self.log(f"[error] Initial fetch: {e}", "red")

    def _render_agents(self, agents):
        self.agents_box.configure(state="normal")
        self.agents_box.delete("1.0", "end")
        for a in agents:
            status = a.get("status", "?")
            host = a.get("hostname", "?")
            ip = a.get("ip_address", "?")
            hb = a.get("last_heartbeat", "")[:19] if a.get("last_heartbeat") else "never"
            self.agents_box.insert("end", f"{'●' if status=='active' else '○'} {host}\n")
            self.agents_box.insert("end", f"  IP: {ip}  |  Last: {hb}\n\n")
        self.agents_box.configure(state="disabled")

    def _update_metrics(self, d):
        try:
            ls = d.get("live_stats", {})
            siem = d.get("siem", {})
            agents = d.get("agents", {})
            self.metrics["Threats"].configure(text=str(siem.get("total", 0)))
            self.metrics["Alerts"].configure(text=str(siem.get("unacknowledged", 0)))
            self.metrics["Agents"].configure(text=f"{agents.get('online', 0)}/{agents.get('total', 0)}")
            self.metrics["CPU"].configure(text=f'{ls.get("cpu_percent", 0):.1f}%')
            self.metrics["Mem"].configure(text=f'{ls.get("memory_mb", 0):.0f} MB')
            self.metrics["Req/s"].configure(text=f'{ls.get("requests_per_second", 0):.1f}')
        except Exception:
            pass

    def sse_loop(self):
        while self._running:
            try:
                resp = requests.get(f"{SERVER}/api/v1/stream", stream=True, timeout=30)
                client = sseclient.SSEClient(resp)
                self.root.after(0, lambda: self.sse_lbl.configure(text="SSE: connected", fg="#4edea3"))
                for event in client.events():
                    if not self._running:
                        break
                    d = json.loads(event.data)
                    self.root.after(0, lambda d=d: self._update_metrics(
                        {"live_stats": d.get("metrics", {}), "siem": {}, "agents": {}}))
            except Exception as e:
                self.root.after(0, lambda: self.sse_lbl.configure(
                    text=f"SSE: disconnected ({type(e).__name__})", fg="#ff4d6d"))
                time.sleep(5)

    def poll_alerts(self):
        last_id = 0
        while self._running:
            try:
                r = requests.get(f"{SERVER}/api/v1/siem/alerts?limit=10", timeout=10)
                if r.status_code == 200:
                    alerts = r.json()
                    if isinstance(alerts, list) and alerts:
                        for a in alerts:
                            aid = a.get("id", 0)
                            if aid > last_id:
                                sev = a.get("severity", "info").upper()
                                desc = a.get("description", a.get("rule_name", "?"))[:60]
                                self.log(f"[{sev}] {desc}")
                                last_id = aid
            except Exception:
                pass
            time.sleep(3)

    def run(self):
        self.update_clock()
        self.fetch_initial()

        threading.Thread(target=self.sse_loop, daemon=True).start()
        threading.Thread(target=self.poll_alerts, daemon=True).start()

        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.mainloop()

    def _close(self):
        self._running = False
        self.root.destroy()

if __name__ == "__main__":
    print("KALKI Desktop — Live SIEM/XDR Monitor")
    print(f"Server: {SERVER}")
    print()
    app = KalkiDesktop()
    app.run()
