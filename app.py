"""نقطة تشغيل نظام NIDS."""
from __future__ import annotations

import os
import sys

# ضمان استيراد الحزمة من مجلد المشروع
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from config import Config

app = create_app(Config)

if __name__ == "__main__":
    # لا تستخدم Debug في النشر العام
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        use_reloader=False,
    )
