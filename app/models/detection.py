"""قواعد الكشف ومصادر المؤشرات."""
from __future__ import annotations

from datetime import datetime, timezone

from app.models import db


class DetectionRule(db.Model):
    __tablename__ = "detection_rules"

    id = db.Column(db.Integer, primary_key=True)
    rule_key = db.Column(db.String(80), unique=True, nullable=False)
    name_ar = db.Column(db.String(120), nullable=False)
    name_en = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(40), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    status = db.Column(db.String(40), default="active", nullable=False)
    # active | disabled | needs_data | unconfigured
    threshold = db.Column(db.Integer, nullable=True)
    window_seconds = db.Column(db.Integer, nullable=True)
    description = db.Column(db.Text, nullable=True)
    requires_source = db.Column(db.String(80), nullable=True)
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_key": self.rule_key,
            "name_ar": self.name_ar,
            "name_en": self.name_en,
            "category": self.category,
            "enabled": self.enabled,
            "status": self.status,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "description": self.description,
            "requires_source": self.requires_source,
        }


class IndicatorFeed(db.Model):
    __tablename__ = "indicator_feeds"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    indicator_type = db.Column(db.String(40), nullable=False)  # ip | domain | hash
    value = db.Column(db.String(255), nullable=False, index=True)
    source = db.Column(db.String(120), nullable=True)
    confidence = db.Column(db.Float, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    last_updated = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    notes = db.Column(db.Text, nullable=True)
