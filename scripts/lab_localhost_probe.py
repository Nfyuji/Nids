"""
مسبار مخبري آمن لجهازك فقط (127.0.0.1).
لا يفحص أجهزة خارجية ولا الإنترنت.

الاستخدام (بعد بدء المراقبة من واجهة NIDS إن رغبت بالتقاط حقيقي):
  .\\.venv\\Scripts\\python.exe scripts\\lab_localhost_probe.py
"""
from __future__ import annotations

import socket
import time

TARGET = "127.0.0.1"
PORTS = list(range(20, 60)) + [80, 443, 22, 3389, 8080]


def main() -> None:
    print(f"[LAB] Connecting to {TARGET} on {len(PORTS)} ports (local only)...")
    ok = 0
    for port in PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        try:
            s.connect_ex((TARGET, port))
            ok += 1
        finally:
            s.close()
        time.sleep(0.02)
    print(f"[LAB] Done. Attempts={ok}. If capture+detection are running, check Alerts.")
    print("[LAB] This script never targets remote hosts.")


if __name__ == "__main__":
    main()
