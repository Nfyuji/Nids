"""نقطة دخول WSGI لـ Gunicorn / Render.

ملاحظة: لا تستخدم `gunicorn app:app` لأن مجلد الحزمة `app/`
يحجب ملف `app.py`. استخدم: gunicorn wsgi:app
"""
from __future__ import annotations

from app import create_app
from config import Config

app = create_app(Config)
