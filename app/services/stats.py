"""إحصائيات حقيقية من قاعدة البيانات — بدون أرقام وهمية."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_

from app.models import db
from app.models.alert import Alert
from app.models.network_event import NetworkEvent
from app.models.sensor import Sensor
from app.models.detection import DetectionRule
from app.services.settings_service import get_setting


ATTACK_LABELS = {
    "port_scan": ("فحص المنافذ", "Port Scanning"),
    "brute_force": ("القوة الغاشمة", "Brute Force"),
    "dos": ("رفض الخدمة", "DoS/DDoS"),
    "ddos": ("رفض الخدمة الموزع", "DDoS"),
    "malware": ("حركة خبيثة", "Malware Traffic"),
    "suspicious": ("اتصال مشبوه", "Suspicious Connections"),
}


def demo_mode_enabled() -> bool:
    return bool(get_setting("demo_mode", False))


def _alert_stats_query():
    """في وضع العرض تُعرض البيانات التجريبية مع شارة؛ خارجها الحقيقية فقط."""
    if demo_mode_enabled():
        return Alert.query
    return Alert.query.filter_by(is_simulated=False)


def _event_stats_filter():
    if demo_mode_enabled():
        return True  # لا فلتر
    return NetworkEvent.is_simulated.is_(False)


def _real_alert_query():
    return Alert.query.filter_by(is_simulated=False)


def dashboard_stats() -> dict:
    sensor = Sensor.query.first()
    capture_active = bool(sensor and sensor.capture_active)
    demo = demo_mode_enabled()
    q = _alert_stats_query()
    total_alerts = q.count()
    critical = q.filter_by(severity="critical").count()
    simulated_count = Alert.query.filter_by(is_simulated=True).count()

    packets = 0
    bytes_total = 0
    if sensor and not demo:
        packets = sensor.packets_captured or 0
        bytes_total = sensor.bytes_captured or 0
    else:
        ev_q = db.session.query(func.coalesce(func.sum(NetworkEvent.packet_count), 0))
        by_q = db.session.query(func.coalesce(func.sum(NetworkEvent.byte_count), 0))
        if not demo:
            ev_q = ev_q.filter_by(is_simulated=False)
            by_q = by_q.filter_by(is_simulated=False)
        packets = ev_q.scalar() or 0
        bytes_total = by_q.scalar() or 0
        if sensor and not demo:
            packets = sensor.packets_captured or packets
            bytes_total = sensor.bytes_captured or bytes_total

    type_q = db.session.query(Alert.attack_type, func.count(Alert.id))
    if not demo:
        type_q = type_q.filter_by(is_simulated=False)
    by_type = dict(type_q.group_by(Alert.attack_type).all())

    standby = not capture_active and total_alerts == 0 and int(packets) == 0 and not demo

    return {
        "standby": standby,
        "demo_mode": demo,
        "simulated_count": simulated_count,
        "capture_active": capture_active,
        "total_packets": int(packets),
        "total_bytes": int(bytes_total),
        "total_alerts": total_alerts,
        "critical_alerts": critical,
        "alerts_by_type": {
            "port_scan": by_type.get("port_scan", 0),
            "brute_force": by_type.get("brute_force", 0),
            "dos": by_type.get("dos", 0) + by_type.get("ddos", 0),
            "malware": by_type.get("malware", 0),
            "suspicious": by_type.get("suspicious", 0),
        },
        "sensor_status": sensor.status if sensor else "standby",
        "suricata_path": get_setting("suricata_eve_path", "") or "",
        "suricata_connected": bool(sensor and sensor.suricata_connected),
        "last_update": datetime.now(timezone.utc).isoformat(),
        "last_activity": sensor.last_activity.isoformat() if sensor and sensor.last_activity else None,
    }


def traffic_timeline(hours: int = 24) -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    demo = demo_mode_enabled()
    ev_filters = [NetworkEvent.observed_at >= since]
    if not demo:
        ev_filters.append(NetworkEvent.is_simulated.is_(False))
    events = (
        NetworkEvent.query.filter(*ev_filters)
        .order_by(NetworkEvent.observed_at.asc())
        .all()
    )
    buckets = defaultdict(lambda: {"normal": 0, "suspicious": 0, "malicious": 0})
    labels = []
    for h in range(hours):
        t = (since + timedelta(hours=h)).replace(minute=0, second=0, microsecond=0)
        key = t.strftime("%H:00")
        labels.append(key)
        buckets[key]  # ensure key exists

    alert_q = _alert_stats_query().filter(Alert.observed_at >= since)
    alert_hours = set()
    for a in alert_q.all():
        if a.observed_at:
            alert_hours.add(
                a.observed_at.replace(minute=0, second=0, microsecond=0).strftime("%H:00")
            )

    for ev in events:
        key = ev.observed_at.replace(minute=0, second=0, microsecond=0).strftime("%H:00")
        if key not in buckets:
            continue
        buckets[key]["normal"] += ev.packet_count or 1

    for a in alert_q.all():
        if not a.observed_at:
            continue
        key = a.observed_at.replace(minute=0, second=0, microsecond=0).strftime("%H:00")
        if key not in buckets:
            continue
        if a.severity in ("critical", "high"):
            buckets[key]["malicious"] += 1
        else:
            buckets[key]["suspicious"] += 1

    return {
        "labels": labels,
        "normal": [buckets[l]["normal"] for l in labels],
        "suspicious": [buckets[l]["suspicious"] for l in labels],
        "malicious": [buckets[l]["malicious"] for l in labels],
        "has_data": bool(events) or bool(alert_hours),
    }


def attack_distribution() -> dict:
    q = db.session.query(Alert.attack_type, func.count(Alert.id))
    if not demo_mode_enabled():
        q = q.filter_by(is_simulated=False)
    rows = q.group_by(Alert.attack_type).all()
    total = sum(c for _, c in rows) or 0
    items = []
    for t, c in rows:
        ar, en = ATTACK_LABELS.get(t, (t, t))
        items.append(
            {
                "type": t,
                "label_ar": ar,
                "label_en": en,
                "count": c,
                "percent": round((c / total) * 100, 1) if total else 0,
            }
        )
    return {"total": total, "items": items, "has_data": total > 0}


def recent_alerts(limit: int = 10, include_simulated: bool = False):
    q = Alert.query
    if not include_simulated and not demo_mode_enabled():
        q = q.filter_by(is_simulated=False)
    return q.order_by(Alert.observed_at.desc()).limit(limit).all()


def top_offenders(limit: int = 8):
    demo = demo_mode_enabled()
    q = db.session.query(Alert.src_ip, func.count(Alert.id)).filter(Alert.src_ip.isnot(None))
    if not demo:
        q = q.filter(Alert.is_simulated.is_(False))
    rows = (
        q.group_by(Alert.src_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
        .all()
    )
    result = []
    for src_ip, count in rows:
        tq = db.session.query(Alert.attack_type, func.count(Alert.id)).filter(
            Alert.src_ip == src_ip
        )
        if not demo:
            tq = tq.filter(Alert.is_simulated.is_(False))
        top_type = (
            tq.group_by(Alert.attack_type)
            .order_by(func.count(Alert.id).desc())
            .first()
        )
        result.append(
            {
                "ip": src_ip,
                "count": count,
                "attack_type": top_type[0] if top_type else "unknown",
            }
        )
    return result


def detection_modules_status() -> list[dict]:
    rules = DetectionRule.query.order_by(DetectionRule.id).all()
    return [r.to_dict() for r in rules]


def ip_investigation(ip: str) -> dict:
    from app.services.local_network import enrich_ip_context

    alerts = (
        Alert.query.filter(
            Alert.is_simulated.is_(False),
            or_(Alert.src_ip == ip, Alert.dst_ip == ip),
        )
        .order_by(Alert.observed_at.desc())
        .all()
    )
    events = (
        NetworkEvent.query.filter(
            NetworkEvent.is_simulated.is_(False),
            or_(NetworkEvent.src_ip == ip, NetworkEvent.dst_ip == ip),
        )
        .order_by(NetworkEvent.observed_at.desc())
        .limit(200)
        .all()
    )
    ports = set()
    protocols = Counter()
    for e in events:
        if e.dst_port:
            ports.add(e.dst_port)
        if e.src_port:
            ports.add(e.src_port)
        if e.protocol:
            protocols[e.protocol] += e.packet_count or 1
    for a in alerts:
        if a.dst_port:
            ports.add(a.dst_port)
        if a.src_port:
            ports.add(a.src_port)
        if a.protocol:
            protocols[a.protocol] += 1

    first_seen = None
    last_seen = None
    times = [a.observed_at for a in alerts if a.observed_at] + [
        e.observed_at for e in events if e.observed_at
    ]
    if times:
        first_seen = min(times)
        last_seen = max(times)

    severities = [a.severity for a in alerts]
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    inferred = "info"
    if severities:
        inferred = max(severities, key=lambda s: severity_rank.get(s, 0))

    try:
        local_ctx = enrich_ip_context(ip)
    except Exception as exc:  # noqa: BLE001
        local_ctx = {
            "ip": ip,
            "is_private": False,
            "roles": [],
            "gateway": None,
            "local_ips": [],
            "arp": None,
            "ping": None,
            "blocked_public_scan": True,
            "message": f"تعذر جمع السياق المحلي: {exc}",
        }
    has_local = bool(
        local_ctx.get("roles")
        or local_ctx.get("arp")
        or (local_ctx.get("ping") or {}).get("reachable")
        or events
        or alerts
    )

    return {
        "ip": ip,
        "alert_count": len(alerts),
        "event_count": len(events),
        "ports": sorted(ports),
        "protocols": dict(protocols),
        "first_seen": first_seen.isoformat() if first_seen else None,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "inferred_severity": inferred,
        "alerts": [a.to_dict() for a in alerts[:50]],
        "events": [e.to_dict() for e in events[:50]],
        "local": local_ctx,
        "has_data": has_local,
        "has_capture_data": bool(alerts or events),
    }
