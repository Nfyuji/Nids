"""كشف الاتصالات المشبوهة."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock

from app.models.detection import IndicatorFeed
from app.services.alert_service import create_alert
from app.services.settings_service import get_exclude_ips, get_setting

ADMIN_PORTS = {22, 23, 3389, 5900, 5901, 445, 139, 21}
_lock = Lock()
_conn_counts: dict[str, list] = defaultdict(list)


def reset_state() -> None:
    with _lock:
        _conn_counts.clear()


def evaluate(meta: dict, rule=None):
    src = meta.get("src_ip")
    dst = meta.get("dst_ip")
    port = meta.get("dst_port")
    if not src:
        return None
    if src in get_exclude_ips():
        return None

    now = meta.get("observed_at") or datetime.now(timezone.utc)
    if getattr(now, "tzinfo", None) is None:
        now = now.replace(tzinfo=timezone.utc)

    # وجهات في قائمة IOC
    if dst:
        ioc = IndicatorFeed.query.filter_by(
            indicator_type="ip", value=dst, is_active=True
        ).first()
        if ioc:
            return create_alert(
                attack_type="suspicious",
                title=f"اتصال مشبوه نحو مؤشر محلي {dst}",
                detection_rule="suspicious_ioc_dst",
                severity="medium",
                src_ip=src,
                dst_ip=dst,
                dst_port=port,
                protocol=meta.get("protocol"),
                description="اتصال بوجهة مدرجة في قائمة مؤشرات محلية.",
                evidence={"indicator": dst, "source": ioc.source},
                confidence=ioc.confidence or 0.6,
                source_type=meta.get("source_type", "detection_engine"),
                is_simulated=bool(meta.get("is_simulated")),
                observed_at=now,
                sensor_id=meta.get("sensor_id"),
            )

    threshold = (rule.threshold if rule and rule.threshold else None) or int(
        get_setting("suspicious_conn_threshold", 10) or 10
    )
    window = (rule.window_seconds if rule and rule.window_seconds else None) or 300

    # اتصالات متكررة لمنافذ إدارية
    if port in ADMIN_PORTS:
        key = f"{src}->{dst}:{port}"
        with _lock:
            entries = _conn_counts[key]
            entries.append(now.timestamp())
            cutoff = now.timestamp() - window
            entries[:] = [t for t in entries if t >= cutoff]
            if len(entries) < threshold:
                return None
            count = len(entries)

        return create_alert(
            attack_type="suspicious",
            title=f"اتصال مشبوه متكرر إلى منفذ إداري {port}",
            detection_rule="suspicious_admin_port",
            severity="low",
            src_ip=src,
            dst_ip=dst,
            dst_port=port,
            protocol=meta.get("protocol"),
            description=(
                f"{count} اتصال إلى المنفذ {port} خلال {window}ث. "
                "قد يكون نشاطاً إدارياً مشروعاً — راجع قائمة الاستثناءات."
            ),
            evidence={
                "connections": count,
                "port": port,
                "window_seconds": window,
                "note": "اتصال مشبوه احتمالي.",
            },
            thresholds={"connections": threshold, "window_seconds": window},
            confidence=0.45,
            source_type=meta.get("source_type", "detection_engine"),
            is_simulated=bool(meta.get("is_simulated")),
            observed_at=now,
            sensor_id=meta.get("sensor_id"),
        )

    return None
