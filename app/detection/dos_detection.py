"""كشف مؤشرات DoS / DDoS."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock

from app.services.alert_service import create_alert
from app.services.settings_service import get_exclude_ips, get_setting

_lock = Lock()
# key bucket -> counters
_packets: list[tuple] = []  # (ts, src, dst, is_syn)
_state_ready = True


def reset_state() -> None:
    with _lock:
        _packets.clear()


def evaluate(meta: dict, rule=None):
    src = meta.get("src_ip")
    dst = meta.get("dst_ip")
    if not src:
        return None
    if src in get_exclude_ips():
        return None

    now = meta.get("observed_at") or datetime.now(timezone.utc)
    if getattr(now, "tzinfo", None) is None:
        now = now.replace(tzinfo=timezone.utc)

    pps_th = (rule.threshold if rule and rule.threshold else None) or int(
        get_setting("dos_pps_threshold", 500) or 500
    )
    syn_th = int(get_setting("dos_syn_threshold", 200) or 200)
    window = (rule.window_seconds if rule and rule.window_seconds else None) or int(
        get_setting("dos_window_seconds", 10) or 10
    )

    flags = (meta.get("flags") or "").upper()
    is_syn = "S" in flags and "A" not in flags

    with _lock:
        _packets.append((now.timestamp(), src, dst, is_syn))
        cutoff = now.timestamp() - window
        _packets[:] = [p for p in _packets if p[0] >= cutoff]

        total = len(_packets)
        syn_count = sum(1 for p in _packets if p[3])
        by_src = defaultdict(int)
        by_dst = defaultdict(int)
        for _, s, d, _ in _packets:
            by_src[s] += 1
            if d:
                by_dst[d] += 1

        pps = total / max(window, 1)
        if pps < pps_th and syn_count < syn_th:
            return None

        unique_sources = len(by_src)
        attack_type = "ddos" if unique_sources >= 5 and pps >= pps_th else "dos"
        # لا نؤكد DDoS من مصدر واحد
        if attack_type == "ddos" and unique_sources < 5:
            attack_type = "dos"

        top_src = max(by_src.items(), key=lambda x: x[1])[0] if by_src else src
        top_dst = max(by_dst.items(), key=lambda x: x[1])[0] if by_dst else dst

        evidence = {
            "packets_in_window": total,
            "approx_pps": round(pps, 2),
            "syn_count": syn_count,
            "unique_sources": unique_sources,
            "window_seconds": window,
            "note": (
                "مؤشر ارتفاع غير طبيعي في الحركة. "
                "لا يُعتبر رفض خدمة مؤكداً دون سياق تشغيلي إضافي."
            ),
        }
        if attack_type == "ddos":
            evidence["note"] = (
                "مؤشر محتمل لرفض خدمة موزع (مصادر متعددة). "
                "يتطلب تحققًا تشغيليًا — ليس تأكيدًا تلقائيًا."
            )

    return create_alert(
        attack_type=attack_type,
        title=f"مؤشر {'DDoS' if attack_type == 'ddos' else 'DoS'} نحو {top_dst or 'هدف غير محدد'}",
        detection_rule="dos_ddos",
        severity="critical" if pps >= pps_th * 2 else "high",
        src_ip=top_src,
        dst_ip=top_dst,
        protocol=meta.get("protocol"),
        description=(
            f"معدل تقريبي {pps:.0f} حزمة/ث خلال {window}ث "
            f"(عتبة {pps_th})، SYN={syn_count}، مصادر={unique_sources}."
        ),
        evidence=evidence,
        thresholds={"pps": pps_th, "syn": syn_th, "window_seconds": window},
        confidence=min(0.9, 0.4 + (pps / (pps_th * 2))),
        source_type=meta.get("source_type", "detection_engine"),
        is_simulated=bool(meta.get("is_simulated")),
        observed_at=now,
        sensor_id=meta.get("sensor_id"),
    )
