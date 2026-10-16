"""بناء بيانات خريطة الشبكة الحية من مصادر محلية حقيقية."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from app.models.alert import Alert
from app.models.network_event import NetworkEvent
from app.services.local_network import get_lan_profile, is_private_ip, read_arp_table
from app.services.settings_service import get_setting
from app.services.stats import demo_mode_enabled


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def build_network_map() -> dict:
    profile = get_lan_profile()
    gateway = profile.get("gateway")
    local_ips = list(profile.get("local_ips") or [])
    primary = local_ips[0] if local_ips else None
    demo = demo_mode_enabled()

    nodes: dict[str, dict] = {}
    links: list[dict] = []

    def upsert(ip: str, **kwargs):
        if not ip:
            return
        cur = nodes.get(ip, {
            "id": ip,
            "ip": ip,
            "label": ip,
            "role": "host",
            "severity": "info",
            "alert_count": 0,
            "packet_count": 0,
            "mac": None,
            "is_private": is_private_ip(ip),
            "is_simulated": False,
        })
        for k, v in kwargs.items():
            if v is None:
                continue
            if k == "alert_count":
                cur["alert_count"] = int(cur.get("alert_count") or 0) + int(v)
            elif k == "packet_count":
                cur["packet_count"] = int(cur.get("packet_count") or 0) + int(v)
            elif k == "severity":
                if SEVERITY_RANK.get(v, 0) >= SEVERITY_RANK.get(cur.get("severity"), 0):
                    cur["severity"] = v
            elif k == "role" and cur.get("role") in ("host", None):
                cur["role"] = v
            elif k == "role" and v in ("gateway", "sensor", "attacker"):
                cur["role"] = v
            else:
                if k not in ("alert_count", "packet_count"):
                    cur[k] = v
        nodes[ip] = cur

    # عقد أساسية
    if gateway:
        upsert(gateway, role="gateway", label=f"الراوتر\n{gateway}", severity="info")
    if primary:
        upsert(primary, role="sensor", label=f"مستشعر NIDS\n{primary}", severity="info")

    # أجهزة ARP المحلية
    try:
        for h in read_arp_table()[:24]:
            ip = h.get("ip")
            if not ip or ip == primary:
                continue
            role = "gateway" if gateway and ip == gateway else "host"
            upsert(ip, role=role, mac=h.get("mac"), label=ip)
            if primary:
                links.append({"source": primary, "target": ip, "kind": "lan", "weight": 1})
    except Exception:
        pass

    if gateway and primary:
        links.append({"source": primary, "target": gateway, "kind": "gateway", "weight": 3})

    # تنبيهات حديثة
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    aq = Alert.query.filter(Alert.observed_at >= since)
    if not demo:
        aq = aq.filter_by(is_simulated=False)
    for a in aq.order_by(Alert.observed_at.desc()).limit(80).all():
        if a.src_ip:
            role = "attacker" if a.severity in ("critical", "high") or not is_private_ip(a.src_ip) else "host"
            upsert(
                a.src_ip,
                role=role,
                severity=a.severity,
                alert_count=1,
                is_simulated=bool(a.is_simulated),
                label=a.src_ip,
            )
        if a.dst_ip:
            upsert(a.dst_ip, severity=a.severity if a.severity != "info" else None, alert_count=0)
        if a.src_ip and a.dst_ip:
            links.append({
                "source": a.src_ip,
                "target": a.dst_ip,
                "kind": "alert",
                "severity": a.severity,
                "weight": 2 + SEVERITY_RANK.get(a.severity, 0),
                "attack_type": a.attack_type,
            })

    # أحداث حركة حديثة
    eq = NetworkEvent.query.filter(NetworkEvent.observed_at >= since)
    if not demo:
        eq = eq.filter_by(is_simulated=False)
    for e in eq.order_by(NetworkEvent.observed_at.desc()).limit(120).all():
        if e.src_ip:
            upsert(e.src_ip, packet_count=e.packet_count or 1, is_simulated=bool(e.is_simulated))
        if e.dst_ip:
            upsert(e.dst_ip, packet_count=e.packet_count or 1)
        if e.src_ip and e.dst_ip:
            links.append({
                "source": e.src_ip,
                "target": e.dst_ip,
                "kind": "traffic" if e.protocol != "ARP" else "lan",
                "weight": 1,
                "protocol": e.protocol,
            })

    # دمج الروابط المتكررة
    link_key = Counter()
    merged = {}
    for L in links:
        key = (L["source"], L["target"], L.get("kind"))
        if key not in merged:
            merged[key] = dict(L)
            link_key[key] = 1
        else:
            merged[key]["weight"] = merged[key].get("weight", 1) + L.get("weight", 1)
            link_key[key] += 1
            if L.get("severity") and SEVERITY_RANK.get(L["severity"], 0) > SEVERITY_RANK.get(
                merged[key].get("severity"), 0
            ):
                merged[key]["severity"] = L["severity"]

    node_list = list(nodes.values())
    # ترتيب الأدوار للعرض
    role_order = {"gateway": 0, "sensor": 1, "attacker": 2, "host": 3}
    node_list.sort(key=lambda n: (role_order.get(n["role"], 9), -n.get("alert_count", 0)))

    # حد أقصى للعقد لوضوح الرسم
    if len(node_list) > 28:
        keep = []
        for n in node_list:
            if n["role"] in ("gateway", "sensor", "attacker") or n.get("alert_count", 0) > 0:
                keep.append(n)
        for n in node_list:
            if len(keep) >= 28:
                break
            if n not in keep:
                keep.append(n)
        keep_ids = {n["id"] for n in keep}
        node_list = keep
        merged = {k: v for k, v in merged.items() if k[0] in keep_ids and k[1] in keep_ids}

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "demo_mode": demo,
        "gateway": gateway,
        "sensor_ip": primary,
        "hostname": profile.get("hostname"),
        "node_count": len(node_list),
        "link_count": len(merged),
        "nodes": node_list,
        "links": list(merged.values()),
        "legend": [
            {"role": "gateway", "label": "بوابة الراوتر", "color": "#0ea5e9"},
            {"role": "sensor", "label": "مستشعر NIDS", "color": "#22c55e"},
            {"role": "host", "label": "جهاز محلي", "color": "#38bdf8"},
            {"role": "attacker", "label": "مصدر تنبيه / مشبوه", "color": "#ef4444"},
        ],
    }
