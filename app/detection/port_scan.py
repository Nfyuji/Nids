"""كشف مؤشرات فحص المنافذ."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock

from app.services.alert_service import create_alert
from app.services.settings_service import get_exclude_ips, get_setting

_lock = Lock()
# src_ip -> list[(timestamp, dst_ip, dst_port)]
_state: dict[str, list] = defaultdict(list)


def reset_state() -> None:
    with _lock:
        _state.clear()


def evaluate(meta: dict, rule=None):
    """meta: src_ip, dst_ip, dst_port, protocol, flags, observed_at, is_simulated, sensor_id"""
    src = meta.get("src_ip")
    dst = meta.get("dst_ip")
    port = meta.get("dst_port")
    if not src or port is None:
        return None
    if src in get_exclude_ips():
        return None

    now = meta.get("observed_at") or datetime.now(timezone.utc)
    if getattr(now, "tzinfo", None) is None:
        now = now.replace(tzinfo=timezone.utc)

    threshold = (rule.threshold if rule and rule.threshold else None) or int(
        get_setting("port_scan_threshold", 20) or 20
    )
    window = (rule.window_seconds if rule and rule.window_seconds else None) or int(
        get_setting("port_scan_window_seconds", 60) or 60
    )

    with _lock:
        entries = _state[src]
        entries.append((now, dst, int(port), meta.get("flags")))
        cutoff = now.timestamp() - window
        entries[:] = [e for e in entries if e[0].timestamp() >= cutoff]
        ports = {e[2] for e in entries}
        destinations = {e[1] for e in entries if e[1]}

        if len(ports) < threshold:
            return None

        evidence = {
            "unique_dst_ports": len(ports),
            "unique_destinations": len(destinations),
            "sample_ports": sorted(list(ports))[:30],
            "window_seconds": window,
            "flags_seen": list({e[3] for e in entries if e[3]})[:10],
            "note": "مؤشر نشاط مشبوه — فحص منافذ محتمل، وليس هجوماً مؤكداً.",
        }
        thresholds = {"port_count": threshold, "window_seconds": window}

    return create_alert(
        attack_type="port_scan",
        title=f"مؤشر فحص منافذ من {src}",
        detection_rule="port_scan",
        severity="high" if len(ports) >= threshold * 2 else "medium",
        src_ip=src,
        dst_ip=dst,
        dst_port=port,
        protocol=meta.get("protocol"),
        description=(
            f"رُصد اتصال المصدر {src} بـ {len(ports)} منفذاً مختلفاً "
            f"خلال {window} ثانية. يُصنّف كمؤشر هجوم محتمل."
        ),
        evidence=evidence,
        thresholds=thresholds,
        confidence=min(0.95, 0.5 + (len(ports) / (threshold * 3))),
        source_type=meta.get("source_type", "detection_engine"),
        is_simulated=bool(meta.get("is_simulated")),
        observed_at=now,
        sensor_id=meta.get("sensor_id"),
    )
