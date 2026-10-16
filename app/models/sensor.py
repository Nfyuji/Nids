"""نموذج المستشعرات."""
from __future__ import annotations

from datetime import datetime, timezone

from app.models import db


class Sensor(db.Model):
    __tablename__ = "sensors"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    hostname = db.Column(db.String(120), nullable=True)
    interface = db.Column(db.String(80), nullable=True)
    status = db.Column(db.String(40), default="stopped", nullable=False)
    # stopped | running | error | no_permission | no_interface | standby
    capture_active = db.Column(db.Boolean, default=False, nullable=False)
    packets_captured = db.Column(db.Integer, default=0, nullable=False)
    bytes_captured = db.Column(db.BigInteger, default=0, nullable=False)
    capture_errors = db.Column(db.Integer, default=0, nullable=False)
    last_activity = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.Text, nullable=True)
    suricata_connected = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "hostname": self.hostname,
            "interface": self.interface,
            "status": self.status,
            "capture_active": self.capture_active,
            "packets_captured": self.packets_captured,
            "bytes_captured": self.bytes_captured,
            "capture_errors": self.capture_errors,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "last_error": self.last_error,
            "suricata_connected": self.suricata_connected,
        }
