"""نقطة دخول WSGI لـ Gunicorn / Render.

يفضّل: gunicorn wsgi:app
أو:    gunicorn app:app  (بعد تصدير app من الحزمة)
"""
from __future__ import annotations

from app import app  # noqa: F401 — يعيد استخدام نسخة الحزمة
