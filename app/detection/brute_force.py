"""كشف القوة الغاشمة من سجلات المصادقة فقط — ليس من حزم TCP."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock

from app.services.alert_service import create_alert
from app.services.settings_service import get_setting

_lock = Lock()
# key (src_ip, username) -> timestamps of failures
_failures: dict[tuple, list] = defaultdict(list)


def reset_state() -> None:
    with _lock:
        _failures.clear()


def evaluate(event: dict, rule=None):
    """
    event: src_ip, username, success(bool), service, observed_at, source_type, is_simulated
    يجب أن يكون success=False لحدث فشل مصادقة موثّق.
    """
    if event.get("success") is True:
        return None
    if event.get("auth_result") not in (None, "failure", "failed", False):
        # نقبل فقط فشلًا صريحًا
        if event.get("success") is not False and event.get("auth_result") != "failure":
            return None

    src = event.get("src_ip")
    if not src:
        return None
    username = event.get("username") or "unknown"
    now = event.get("observed_at") or datetime.now(timezone.utc)
    if getattr(now, "tzinfo", None) is None:
        now = now.replace(tzinfo=timezone.utc)

    threshold = (rule.threshold if rule and rule.threshold else None) or int(
        get_setting("brute_force_threshold", 5) or 5
    )
    window = (rule.window_seconds if rule and rule.window_seconds else None) or int(
        get_setting("brute_force_window_seconds", 300) or 300
    )

    key = (src, username)
    with _lock:
        entries = _failures[key]
        entries.append(now.timestamp())
        cutoff = now.timestamp() - window
        entries[:] = [t for t in entries if t >= cutoff]
        count = len(entries)
        if count < threshold:
            return None
        evidence = {
            "failed_attempts": count,
            "username": username,
            "service": event.get("service"),
            "window_seconds": window,
            "note": "فشل مصادقة متكرر من سجل موثّق — مؤشر قوة غاشمة محتمل.",
        }

    return create_alert(
        attack_type="brute_force",
        title=f"مؤشر قوة غاشمة من {src} على الحساب {username}",
        detection_rule="brute_force",
        severity="high" if count >= threshold * 2 else "medium",
        src_ip=src,
        dst_ip=event.get("dst_ip"),
        protocol=event.get("protocol") or event.get("service"),
        description=(
            f"{count} محاولة مصادقة فاشلة خلال {window} ثانية "
            f"ضد الحساب '{username}' عبر {event.get('service', 'unknown')}."
        ),
        evidence=evidence,
        thresholds={"failures": threshold, "window_seconds": window},
        confidence=min(0.92, 0.55 + count / (threshold * 4)),
        source_type=event.get("source_type", "auth_log"),
        is_simulated=bool(event.get("is_simulated")),
        observed_at=now,
        sensor_id=event.get("sensor_id"),
    )
