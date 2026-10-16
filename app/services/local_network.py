"""اكتشاف وفحص محدود للشبكة المحلية الخاصة فقط (LAN) — بدون إنترنت."""
from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from datetime import datetime, timezone
from typing import Any

from app.models import db
from app.models.network_event import NetworkEvent
from app.models.sensor import Sensor


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return bool(addr.is_private or addr.is_link_local or addr.is_loopback)


def _run(cmd: list[str], timeout: int = 8) -> str:
    try:
        flags = 0
        if platform.system() == "Windows":
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            creationflags=flags,
        )
        return (completed.stdout or "") + "\n" + (completed.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return f"ERROR: {exc}"


def get_lan_profile() -> dict[str, Any]:
    """ملخص واجهات/بوابة الشبكة المحلية من الجهاز الحالي."""
    hostname = socket.gethostname()
    local_ips: list[str] = []
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and ip not in local_ips:
                local_ips.append(ip)
    except socket.gaierror:
        pass

    # عناوين إضافية عبر الربط بمأخذ UDP (لا يرسل بيانات)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.168.0.1", 80))
        primary = s.getsockname()[0]
        s.close()
        if primary and primary not in local_ips:
            local_ips.insert(0, primary)
    except OSError:
        pass

    gateway = None
    adapters: list[dict] = []

    if platform.system() == "Windows":
        out = _run(["ipconfig"])
        current: dict[str, Any] = {"name": ""}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            lower = line.lower()
            if line.endswith(":") and (
                "adapter" in lower
                or "محول" in line
                or "ethernet" in lower
                or "wi-fi" in lower
                or "wireless" in lower
                or "lan" in lower
            ):
                if current.get("name"):
                    adapters.append(current)
                current = {"name": line.rstrip(":"), "ipv4": None, "gateway": None, "mask": None}
            m = re.search(r"IPv4[^:]*:\s*([\d\.]+)", line, re.I)
            if not m:
                m = re.search(r"عنوان IPv4[^:]*:\s*([\d\.]+)", line)
            if m:
                current["ipv4"] = m.group(1)
                if m.group(1) not in local_ips:
                    local_ips.append(m.group(1))
            m = re.search(r"(?:Subnet Mask|قناع[^:]*):\s*([\d\.]+)", line, re.I)
            if m:
                current["mask"] = m.group(1)
            m = re.search(r"(?:Default Gateway|البوابة[^:]*):\s*([\d\.]+)", line, re.I)
            if m:
                current["gateway"] = m.group(1)
                if not gateway:
                    gateway = m.group(1)
        if current.get("name"):
            adapters.append(current)

        # احتياطي: جدول التوجيه الافتراضي
        if not gateway:
            route_out = _run(["route", "print", "0.0.0.0"])
            for line in route_out.splitlines():
                m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+([\d\.]+)", line)
                if m and is_private_ip(m.group(1)):
                    gateway = m.group(1)
                    break
    else:
        out = _run(["ip", "route"])
        m = re.search(r"default via ([\d\.]+)", out)
        if m:
            gateway = m.group(1)

    private_ips = [ip for ip in local_ips if is_private_ip(ip)]

    # إن لم تُعرف البوابة: استنتج .1 من شبكة 192.168.x إن وُجدت في ARP لاحقاً عبر المستدعي
    if not gateway:
        for ip in private_ips:
            try:
                net = ipaddress.ip_interface(f"{ip}/24").network
                candidate = str(list(net.hosts())[0])  # غالباً .1
                # تفضيل x.x.x.1
                parts = ip.split(".")
                if len(parts) == 4:
                    candidate = ".".join(parts[:3] + ["1"])
                    gateway = candidate
                    break
            except ValueError:
                continue

    return {
        "hostname": hostname,
        "local_ips": private_ips or local_ips,
        "gateway": gateway,
        "adapters": [a for a in adapters if a.get("ipv4")],
        "platform": platform.system(),
        "scope": "local_private_lan_only",
    }


def read_arp_table() -> list[dict[str, str]]:
    """قراءة جدول ARP المحلي (سلبي — لا يفحص الإنترنت)."""
    hosts: list[dict[str, str]] = []
    if platform.system() == "Windows":
        out = _run(["arp", "-a"])
        # مثال: 192.168.0.1           aa-bb-cc-dd-ee-ff     dynamic
        for line in out.splitlines():
            m = re.search(
                r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-:]{11,})\s+(\w+)",
                line,
            )
            if not m:
                continue
            ip, mac, typ = m.group(1), m.group(2), m.group(3)
            if not is_private_ip(ip):
                continue
            if mac.lower().replace("-", "") in ("ffffffffffff", "000000000000"):
                continue
            hosts.append({"ip": ip, "mac": mac.replace("-", ":").lower(), "type": typ})
    else:
        out = _run(["arp", "-an"])
        for line in out.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)", line, re.I)
            if not m:
                continue
            ip, mac = m.group(1), m.group(2)
            if is_private_ip(ip):
                hosts.append({"ip": ip, "mac": mac.lower(), "type": "arp"})
    # إزالة التكرار
    seen = set()
    unique = []
    for h in hosts:
        if h["ip"] in seen:
            continue
        seen.add(h["ip"])
        unique.append(h)
    return unique


def ping_local(ip: str, timeout_ms: int = 1000) -> dict[str, Any]:
    """فحص وصول ICMP لعنوان خاص محلي فقط."""
    ip = (ip or "").strip()
    if not is_private_ip(ip):
        return {
            "ok": False,
            "reachable": False,
            "error": "يُسمح بالفحص فقط لعناوين الشبكة الخاصة (LAN)، وليس الإنترنت.",
            "ip": ip,
        }
    if platform.system() == "Windows":
        # -n 1 مرة واحدة، -w مهلة بالميلي ثانية
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    out = _run(cmd, timeout=5)
    reachable = (
        "TTL=" in out.upper()
        or "ttl=" in out
        or "bytes from" in out.lower()
        or "رد من" in out
        or "Reply from" in out
    )
    return {
        "ok": True,
        "ip": ip,
        "reachable": reachable,
        "detail": out.strip()[:400],
        "note": "فحص ICMP محلي فقط — لا يؤكد هجوماً ولا يفحص منافذ.",
    }


def import_arp_as_events() -> dict[str, Any]:
    """يستورد أجهزة جدول ARP كأحداث شبكة حقيقية محلية (ليست تجريبية)."""
    profile = get_lan_profile()
    hosts = read_arp_table()
    sensor = Sensor.query.first()
    sensor_id = sensor.id if sensor else None
    local_ip = (profile.get("local_ips") or [None])[0]
    now = datetime.now(timezone.utc)
    created = 0

    # سجّل البوابة إن وُجدت حتى لو لم تكن في ARP بعد
    gateway = profile.get("gateway")
    seed_hosts = list(hosts)
    if gateway and is_private_ip(gateway) and not any(h["ip"] == gateway for h in seed_hosts):
        seed_hosts.insert(0, {"ip": gateway, "mac": "", "type": "gateway"})

    for h in seed_hosts:
        ip = h["ip"]
        # لا تكرر نفس الحدث ARP لنفس الوجهة خلال الدقائق الأخيرة بشكل مزعج
        exists = (
            NetworkEvent.query.filter_by(
                dst_ip=ip, protocol="ARP", source_type="local_arp", is_simulated=False
            )
            .order_by(NetworkEvent.observed_at.desc())
            .first()
        )
        if exists and exists.observed_at:
            prev = exists.observed_at
            if prev.tzinfo is None:
                prev = prev.replace(tzinfo=timezone.utc)
            if (now - prev).total_seconds() < 120:
                continue
        ev = NetworkEvent(
            observed_at=now,
            src_ip=local_ip,
            dst_ip=ip,
            protocol="ARP",
            packet_count=1,
            byte_count=0,
            flags=h.get("mac") or None,
            source_type="local_arp",
            is_simulated=False,
            sensor_id=sensor_id,
        )
        db.session.add(ev)
        created += 1

    if sensor and created:
        sensor.packets_captured = (sensor.packets_captured or 0) + created
        sensor.last_activity = now
        if sensor.status in ("standby", "stopped", "error", "no_permission", "no_interface"):
            sensor.status = "standby"
        sensor.last_error = None
    db.session.commit()
    return {
        "imported": created,
        "hosts_seen": len(seed_hosts),
        "gateway": gateway,
        "local_ips": profile.get("local_ips"),
        "hosts": seed_hosts[:50],
    }


def enrich_ip_context(ip: str) -> dict[str, Any]:
    """سياق محلي لعنوان IP داخل الشبكة الخاصة."""
    ip = (ip or "").strip()
    profile = get_lan_profile()
    arp = {h["ip"]: h for h in read_arp_table()}
    private = is_private_ip(ip)
    roles = []
    if ip in (profile.get("local_ips") or []):
        roles.append("هذا الجهاز")
    if profile.get("gateway") and ip == profile["gateway"]:
        roles.append("بوابة الراوتر / Default Gateway")
    if ip in arp:
        roles.append("ظاهر في جدول ARP المحلي")

    ping = None
    if private:
        ping = ping_local(ip)

    return {
        "ip": ip,
        "is_private": private,
        "roles": roles,
        "gateway": profile.get("gateway"),
        "local_ips": profile.get("local_ips"),
        "arp": arp.get(ip),
        "ping": ping,
        "blocked_public_scan": not private,
        "message": (
            None
            if private
            else "هذا العنوان ليس ضمن شبكة خاصة؛ لن يُنفَّذ أي فحص نشط خارج الشبكة المحلية."
        ),
    }
