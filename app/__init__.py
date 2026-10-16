"""تهيئة تطبيق Flask لنظام NIDS."""
from __future__ import annotations

from flask import Flask
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

    with app.app_context():
        db.create_all()
        from app.services.bootstrap import ensure_defaults

        ensure_defaults(app)

    return app
