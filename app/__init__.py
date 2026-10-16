"""تهيئة تطبيق Flask لنظام NIDS."""
from __future__ import annotations

import os
import traceback

from flask import Flask, render_template_string, request
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

from config import Config
from app.models import db
from app.models.user import User

login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)

    # Render / reverse proxy HTTPS
    try:
        from werkzeug.middleware.proxy_fix import ProxyFix

        if os.environ.get("RENDER"):
            app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    except Exception:
        pass

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "يرجى تسجيل الدخول للمتابعة."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.api import api_bp
    from app.routes.alerts import alerts_bp
    from app.routes.sensors import sensors_bp
    from app.routes.settings import settings_bp
    from app.routes.reports import reports_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(alerts_bp, url_prefix="/alerts")
    app.register_blueprint(sensors_bp, url_prefix="/sensors")
    app.register_blueprint(settings_bp, url_prefix="/settings")
    app.register_blueprint(reports_bp, url_prefix="/reports")

    @app.errorhandler(500)
    def handle_500(err):
        app.logger.error("500 on %s\n%s", request.path, traceback.format_exc())
        # رسالة عربية أوضح بدل الصفحة الإنجليزية الافتراضية
        return (
            render_template_string(
                """
<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<title>خطأ | NIDS</title>
<style>
 body{font-family:Tahoma,sans-serif;background:#f1f5f9;color:#0f172a;padding:2rem}
 .box{max-width:640px;margin:auto;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:1.5rem}
 a{color:#0284c7}
 code{background:#f1f5f9;padding:.2rem .4rem;border-radius:6px}
</style></head><body><div class="box">
<h1>حدث خطأ داخل الصفحة</h1>
<p>المسار: <code>{{ path }}</code></p>
<p>{{ message }}</p>
<p><a href="/dashboard">لوحة التحكم</a> · <a href="/reports/">التقارير</a> · <a href="/">الرئيسية</a></p>
</div></body></html>
                """,
                path=request.path,
                message=str(err) or "خطأ غير متوقع. حدّث الصفحة أو عد للوحة التحكم.",
            ),
            500,
        )

    with app.app_context():
        db.create_all()
        from app.services.bootstrap import ensure_defaults

        ensure_defaults(app)

    return app
