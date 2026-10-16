"""أحداث حركة الشبكة المجمّعة."""
from __future__ import annotations

from datetime import datetime, timezone

from app.models import db


class NetworkEvent(db.Model):
    __tablename__ = "network_events"

    id = db.Column(db.Integer, primary_key=True)
    observed_at = db.Column(db.DateTime, nullable=False, index=True)
    src_ip = db.Column(db.String(45), nullable=True, index=True)
    dst_ip = db.Column(db.String(45), nullable=True, index=True)
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(20), nullable=True, index=True)
    packet_count = db.Column(db.Integer, default=1, nullable=False)
    byte_count = db.Column(db.Integer, default=0, nullable=False)
    flags = db.Column(db.String(40), nullable=True)
    source_type = db.Column(db.String(40), default="scapy", nullable=False)
    is_simulated = db.Column(db.Boolean, default=False, nullable=False, index=True)
    sensor_id = db.Column(db.Integer, db.ForeignKey("sensors.id"), nullable=True)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "flags": self.flags,
            "source_type": self.source_type,
            "is_simulated": self.is_simulated,
        }
