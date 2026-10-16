"""إنشاء وإدارة التنبيهات مع منع التكرار."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from app.models import db
from app.models.alert import Alert
from app.services.settings_service import get_setting

ATTACK_AR = {
    "port_scan": "فحص المنافذ",
    "brute_force": "القوة الغاشمة",
    "dos": "رفض الخدمة",
    "ddos": "رفض الخدمة الموزع",
    "malware": "مؤشر حركة خبيثة",
    "suspicious": "اتصال مشبوه",
}


def _uid(*parts) -> str:
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def create_alert(
    *,
    attack_type: str,
    title: str,
    detection_rule: str,
    severity: str = "medium",
    src_ip: str | None = None,
    dst_ip: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    protocol: str | None = None,
    description: str | None = None,
    evidence: dict | None = None,
    thresholds: dict | None = None,
    confidence: float | None = None,
    source_type: str = "detection_engine",
    is_simulated: bool = False,
    observed_at: datetime | None = None,
    external_sid: str | None = None,
    sensor_id: int | None = None,
    dedup: bool = True,
) -> Alert | None:
    observed_at = observed_at or datetime.now(timezone.utc)
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)

    dedup_key = _uid(
        attack_type,
        src_ip or "",
        dst_ip or "",
        detection_rule,
        external_sid or "",
        "sim" if is_simulated else "real",
    )

    if dedup:
        window = int(get_setting("alert_dedup_seconds", 120) or 120)
        since = observed_at - timedelta(seconds=window)
        existing = (
            Alert.query.filter(
                Alert.alert_uid == dedup_key,
                Alert.observed_at >= since,
            ).first()
        )
        if existing:
            return None
        # أيضاً مطابقة حسب الحقول إن اختلف المعرف الخارجي
        existing2 = (
            Alert.query.filter(
                Alert.attack_type == attack_type,
                Alert.src_ip == src_ip,
                Alert.dst_ip == dst_ip,
                Alert.detection_rule == detection_rule,
                Alert.is_simulated == is_simulated,
                Alert.observed_at >= since,
            ).first()
        )
        if existing2 and not external_sid:
            return None

    # معرف فريد للسجل؛ نستخدم dedup_key كأساس مع لاحقة زمنية عند التعارض
    alert_uid = dedup_key
    if Alert.query.filter_by(alert_uid=alert_uid).first():
        alert_uid = f"{dedup_key}-{uuid.uuid4().hex[:8]}"

    alert = Alert(
        alert_uid=alert_uid,
        observed_at=observed_at,
        attack_type=attack_type,
        attack_type_ar=ATTACK_AR.get(attack_type, attack_type),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        severity=severity,
        confidence=confidence,
        detection_rule=detection_rule,
        source_type=source_type,
        is_simulated=is_simulated,
        status="new",
        title=title,
        description=description,
        external_sid=external_sid,
        sensor_id=sensor_id,
    )
    if evidence:
        alert.set_evidence(evidence)
    if thresholds:
        alert.set_thresholds(thresholds)
    db.session.add(alert)
    db.session.commit()
    return alert


def update_status(alert: Alert, new_status: str, user_id: int, note: str | None = None):
    from app.models.alert import InvestigationNote

    old = alert.status
    alert.status = new_status
    entry = InvestigationNote(
        alert_id=alert.id,
        user_id=user_id,
        note=note or f"تغيير الحالة من {old} إلى {new_status}",
        old_status=old,
        new_status=new_status,
    )
    db.session.add(entry)
    db.session.commit()
    return alert
