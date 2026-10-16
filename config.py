"""إعدادات تطبيق NIDS."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)

load_dotenv(BASE_DIR / ".env")


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL") or f"sqlite:///{INSTANCE_DIR / 'nids.db'}"
    # Render/Heroku قد تُرجع postgres:// — SQLAlchemy يحتاج postgresql://
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True

    CAPTURE_INTERFACE = os.environ.get("CAPTURE_INTERFACE", "")
    CAPTURE_BPF_FILTER = os.environ.get("CAPTURE_BPF_FILTER", "tcp or udp or icmp")
    SURICATA_EVE_PATH = os.environ.get("SURICATA_EVE_PATH", "")
    TIMEZONE = os.environ.get("TIMEZONE", "Asia/Riyadh")
    LOG_RETENTION_DAYS = int(os.environ.get("LOG_RETENTION_DAYS", "30"))

    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@localhost")

    HOST = os.environ.get("HOST", "0.0.0.0" if os.environ.get("RENDER") else "127.0.0.1")
    PORT = int(os.environ.get("PORT", "5000"))
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
    # خلف بروكسي Render (HTTPS)
    PREFERRED_URL_SCHEME = "https" if os.environ.get("RENDER") else "http"
    SESSION_COOKIE_SECURE = os.environ.get("RENDER") == "true" or os.environ.get(
        "SESSION_COOKIE_SECURE", "0"
    ) == "1"

    # عتبات الكشف الافتراضية
    PORT_SCAN_THRESHOLD = int(os.environ.get("PORT_SCAN_THRESHOLD", "20"))
    PORT_SCAN_WINDOW_SECONDS = int(os.environ.get("PORT_SCAN_WINDOW_SECONDS", "60"))
    DOS_PPS_THRESHOLD = int(os.environ.get("DOS_PPS_THRESHOLD", "500"))
    DOS_SYN_THRESHOLD = int(os.environ.get("DOS_SYN_THRESHOLD", "200"))
    DOS_WINDOW_SECONDS = int(os.environ.get("DOS_WINDOW_SECONDS", "10"))
    BRUTE_FORCE_THRESHOLD = int(os.environ.get("BRUTE_FORCE_THRESHOLD", "5"))
    BRUTE_FORCE_WINDOW_SECONDS = int(os.environ.get("BRUTE_FORCE_WINDOW_SECONDS", "300"))
    ALERT_DEDUP_SECONDS = int(os.environ.get("ALERT_DEDUP_SECONDS", "120"))

    THEME_DEFAULT = os.environ.get("THEME_DEFAULT", "light")
