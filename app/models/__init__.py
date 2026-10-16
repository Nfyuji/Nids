"""نماذج قاعدة البيانات."""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from app.models.user import User  # noqa: E402,F401
from app.models.alert import Alert, InvestigationNote  # noqa: E402,F401
from app.models.sensor import Sensor  # noqa: E402,F401
from app.models.network_event import NetworkEvent  # noqa: E402,F401
from app.models.settings import ApplicationSetting, AuditLog  # noqa: E402,F401
from app.models.detection import DetectionRule, IndicatorFeed  # noqa: E402,F401
