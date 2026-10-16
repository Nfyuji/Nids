"""اختبار إنشاء قاعدة البيانات."""
from app.models import db
from app.models.user import User
from app.models.sensor import Sensor
from app.models.detection import DetectionRule
from app.models.settings import ApplicationSetting


def test_database_bootstrap(app):
    with app.app_context():
        assert User.query.filter_by(username="admin").first() is not None
        assert Sensor.query.count() >= 1
        assert DetectionRule.query.count() >= 5
        assert ApplicationSetting.query.count() >= 5
        admin = User.query.filter_by(username="admin").first()
        assert admin.password_hash != "test-admin-pass-123"
        assert admin.check_password("test-admin-pass-123")
