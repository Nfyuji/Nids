"""نماذج التنبيهات والتحقيق."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from app.models import db

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("new", "investigating", "reviewed", "closed")
SOURCE_TYPES = ("scapy", "suricata", "auth_log", "manual", "detection_engine", "simulated")


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    alert_uid = db.Column(db.String(64), unique=True, nullable=False, index=True)
    observed_at = db.Column(db.DateTime, nullable=False, index=True)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    attack_type = db.Column(db.String(64), nullable=False, index=True)
    attack_type_ar = db.Column(db.String(80), nullable=True)
    src_ip = db.Column(db.String(45), nullable=True, index=True)
    dst_ip = db.Column(db.String(45), nullable=True, index=True)
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(20), nullable=True)
    severity = db.Column(db.String(20), nullable=False, default="medium", index=True)
    confidence = db.Column(db.Float, nullable=True)
    detection_rule = db.Column(db.String(120), nullable=False)
    source_type = db.Column(db.String(40), nullable=False, default="detection_engine")
    is_simulated = db.Column(db.Boolean, default=False, nullable=False, index=True)
    status = db.Column(db.String(20), default="new", nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    evidence_json = db.Column(db.Text, nullable=True)
    thresholds_json = db.Column(db.Text, nullable=True)
    external_sid = db.Column(db.String(64), nullable=True, index=True)
    sensor_id = db.Column(db.Integer, db.ForeignKey("sensors.id"), nullable=True)

    notes = db.relationship("InvestigationNote", back_populates="alert", lazy="dynamic")

    __table_args__ = (
        db.Index("ix_alerts_src_dst", "src_ip", "dst_ip"),
        db.Index("ix_alerts_type_sev", "attack_type", "severity"),
    )

    def get_evidence(self) -> dict:
        if not self.evidence_json:
            return {}
        try:
            return json.loads(self.evidence_json)
        except json.JSONDecodeError:
            return {}

    def set_evidence(self, data: dict) -> None:
        self.evidence_json = json.dumps(data, ensure_ascii=False)

    def get_thresholds(self) -> dict:
        if not self.thresholds_json:
            return {}
        try:
            return json.loads(self.thresholds_json)
        except json.JSONDecodeError:
            return {}

    def set_thresholds(self, data: dict) -> None:
        self.thresholds_json = json.dumps(data, ensure_ascii=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "alert_uid": self.alert_uid,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "attack_type": self.attack_type,
            "attack_type_ar": self.attack_type_ar,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "severity": self.severity,
            "confidence": self.confidence,
            "detection_rule": self.detection_rule,
            "source_type": self.source_type,
            "is_simulated": self.is_simulated,
            "status": self.status,
            "title": self.title,
            "description": self.description,
            "evidence": self.get_evidence(),
            "thresholds": self.get_thresholds(),
            "external_sid": self.external_sid,
        }


class InvestigationNote(db.Model):
    __tablename__ = "investigations"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    note = db.Column(db.Text, nullable=False)
    old_status = db.Column(db.String(20), nullable=True)
    new_status = db.Column(db.String(20), nullable=True)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    alert = db.relationship("Alert", back_populates="notes")
    user = db.relationship("User")
