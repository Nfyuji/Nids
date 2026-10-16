"""سيناريو عرض توضيحي لمشروع التخرج — بيانات تجريبية معلّمة بوضوح."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.detection import brute_force, dos_detection, port_scan
from app.detection.brute_force import reset_state as reset_bf
from app.detection.dos_detection import reset_state as reset_dos
from app.detection.port_scan import reset_state as reset_ps
from app.models import db
from app.models.alert import Alert
from app.models.network_event import NetworkEvent
from app.services.alert_service import create_alert
from app.services.settings_service import set_setting


ATTACKER = "198.51.100.66"  # TEST-NET-2 — عنوان وثائقي للاختبار فقط
VICTIM = "192.168.0.10"
GATEWAY = "192.168.0.1"


def run_graduation_demo() -> dict:
    """
    يشغّل سيناريو هجوم مخبري آمن (تجريبي):
    فحص منافذ + مؤشرات DoS + قوة غاشمة من سجل مصادقة + اتصال مشبوه.
    كل السجلات is_simulated=True ومصدرها demo_lab.
    """
    reset_ps()
    reset_dos()
    reset_bf()
    set_setting("demo_mode", True)
    set_setting("alert_dedup_seconds", 1)
    # لا تستثنِ عنوان العرض من الكشف أثناء السيناريو
    set_setting("exclude_ips", "::1")

    now = datetime.now(timezone.utc)
    created_alerts = 0
    created_events = 0

    # أحداث حركة تجريبية للوحة والخطوط الزمنية
    for i in range(24):
        ts = now - timedelta(minutes=5 * i)
        db.session.add(
            NetworkEvent(
                observed_at=ts,
                src_ip=ATTACKER if i % 3 == 0 else "192.168.0.101",
                dst_ip=VICTIM if i % 3 == 0 else GATEWAY,
                src_port=40000 + i,
                dst_port=80 if i % 2 == 0 else 443,
                protocol="TCP",
                packet_count=3 + (i % 5),
                byte_count=200 + i * 10,
                flags="S" if i % 4 == 0 else "PA",
                source_type="demo_lab",
                is_simulated=True,
            )
        )
        created_events += 1
    db.session.commit()

    # 1) فحص منافذ — عبر محرك الكشف الحقيقي ببيانات تجريبية
    for port in range(20, 45):
        alert = port_scan.evaluate(
            {
                "src_ip": ATTACKER,
                "dst_ip": VICTIM,
                "dst_port": port,
                "protocol": "TCP",
                "flags": "S",
                "observed_at": now,
                "is_simulated": True,
                "source_type": "demo_lab",
            }
        )
        if alert:
            created_alerts += 1

    # 2) مؤشرات DoS (عتبة منخفضة مؤقتاً للعرض)
    from app.services.settings_service import set_setting as _set

    _set("dos_pps_threshold", 20)
    _set("dos_syn_threshold", 8)
    _set("dos_window_seconds", 10)
    for i in range(25):
        alert = dos_detection.evaluate(
            {
                "src_ip": f"198.51.100.{10 + (i % 6)}",
                "dst_ip": VICTIM,
                "protocol": "TCP",
                "flags": "S",
                "observed_at": now,
                "is_simulated": True,
                "source_type": "demo_lab",
            }
        )
        if alert:
            created_alerts += 1

    # 3) قوة غاشمة من أحداث مصادقة تجريبية
    _set("brute_force_threshold", 3)
    for _ in range(5):
        alert = brute_force.evaluate(
            {
                "src_ip": ATTACKER,
                "username": "admin",
                "success": False,
                "auth_result": "failure",
                "service": "ssh",
                "dst_ip": VICTIM,
                "observed_at": now,
                "is_simulated": True,
                "source_type": "demo_lab",
            }
        )
        if alert:
            created_alerts += 1

    # 4) اتصال مشبوه مباشر
    a = create_alert(
        attack_type="suspicious",
        title="[عرض] اتصال مشبوه بمنفذ إداري 3389",
        detection_rule="demo_suspicious_rdp",
        severity="medium",
        src_ip=ATTACKER,
        dst_ip=VICTIM,
        dst_port=3389,
        protocol="TCP",
        description="سيناريو عرض توضيحي لمشروع التخرج — ليس هجوماً حقيقياً.",
        evidence={"note": "بيانات DEMO معلّمة is_simulated=True", "scenario": "graduation"},
        confidence=0.55,
        source_type="demo_lab",
        is_simulated=True,
        observed_at=now,
        dedup=False,
    )
    if a:
        created_alerts += 1

    a = create_alert(
        attack_type="malware",
        title="[عرض] تطابق مؤشر محلي تجريبي",
        detection_rule="demo_malware_ioc",
        severity="high",
        src_ip="192.168.0.55",
        dst_ip=ATTACKER,
        dst_port=4444,
        protocol="TCP",
        description="مؤشر تهديد محلي في سيناريو العرض — للاختبار الأكاديمي فقط.",
        evidence={"indicator": ATTACKER, "feed_source": "demo_lab"},
        confidence=0.7,
        source_type="demo_lab",
        is_simulated=True,
        observed_at=now - timedelta(minutes=2),
        dedup=False,
    )
    if a:
        created_alerts += 1

    # إعادة عتبات معقولة بعد العرض
    _set("dos_pps_threshold", 500)
    _set("dos_syn_threshold", 200)
    _set("brute_force_threshold", 5)
    _set("alert_dedup_seconds", 120)
    _set("exclude_ips", "127.0.0.1,::1")

    return {
        "alerts": created_alerts,
        "events": created_events,
        "attacker": ATTACKER,
        "victim": VICTIM,
        "demo_mode": True,
        "note": "كل البيانات تحمل شارة تجريبي / demo_lab",
    }


def clear_demo_data() -> dict:
    """يحذف بيانات العرض التجريبي ويطفئ وضع العرض."""
    from sqlalchemy import or_

    alerts = Alert.query.filter(
        or_(Alert.is_simulated.is_(True), Alert.source_type == "demo_lab")
    ).delete(synchronize_session=False)
    events = NetworkEvent.query.filter(
        or_(NetworkEvent.is_simulated.is_(True), NetworkEvent.source_type == "demo_lab")
    ).delete(synchronize_session=False)
    set_setting("demo_mode", False)
    db.session.commit()
    return {"deleted_alerts": alerts, "deleted_events": events, "demo_mode": False}
