"""مستشعر التقاط الحزم عبر Scapy — يعمل اختيارياً ويتطلب صلاحيات/Npcap."""
from __future__ import annotations

import socket
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from flask import Flask

from app.models import db
from app.models.network_event import NetworkEvent
from app.models.sensor import Sensor
from app.services.settings_service import get_setting

_scapy_available = False
_scapy_error = None
try:
    from scapy.all import IP, TCP, UDP, ICMP, sniff, get_if_list  # type: ignore

    _scapy_available = True
except Exception as exc:  # noqa: BLE001
    _scapy_error = str(exc)
    get_if_list = None  # type: ignore


class CaptureManager:
    """مدير التقاط واحد لكل عملية تطبيق."""

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._app: Optional[Flask] = None
        self._packet_buffer: list[dict] = []
        self._buffer_lock = threading.Lock()
        self._last_flush = time.time()
        self.runtime_error: Optional[str] = None
        self.packets_per_second = 0.0
        self._pps_window: list[float] = []

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def list_interfaces(self) -> list[str]:
        if not _scapy_available or get_if_list is None:
            return []
        try:
            return list(get_if_list())
        except Exception:
            return []

    def scapy_status(self) -> dict:
        return {
            "available": _scapy_available,
            "error": _scapy_error,
            "running": self.is_running,
            "runtime_error": self.runtime_error,
            "interfaces": self.list_interfaces(),
            "hint": (
                None
                if _scapy_available
                else "ثبّت Scapy وNpcap على Windows، وشغّل التطبيق بصلاحيات مناسبة."
            ),
        }

    def start(self, app: Flask) -> tuple[bool, str]:
        if self.is_running:
            return False, "الالتقاط يعمل بالفعل."
        if not _scapy_available:
            msg = (
                "Scapy غير متاح. "
                + (_scapy_error or "ثبّت الحزمة وتحقق من Npcap على Windows.")
            )
            self._update_sensor(app, status="error", error=msg, active=False)
            return False, msg

        iface = get_setting("capture_interface", "") or app.config.get("CAPTURE_INTERFACE") or ""
        if not iface:
            interfaces = self.list_interfaces()
            if not interfaces:
                msg = "لا توجد واجهة شبكة متاحة للالتقاط."
                self._update_sensor(app, status="no_interface", error=msg, active=False)
                return False, msg
            iface = interfaces[0]

        self._app = app
        self._stop.clear()
        self.runtime_error = None
        self._thread = threading.Thread(
            target=self._run_capture,
            args=(iface,),
            name="nids-capture",
            daemon=True,
        )
        self._thread.start()
        self._update_sensor(
            app, status="running", error=None, active=True, interface=iface
        )
        return True, f"بدأ الالتقاط على الواجهة: {iface}"

    def stop(self, app: Flask) -> tuple[bool, str]:
        if not self.is_running:
            self._update_sensor(app, status="stopped", active=False)
            return True, "الالتقاط متوقف بالفعل."
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None
        self._flush(app)
        self._update_sensor(app, status="stopped", active=False)
        return True, "تم إيقاف الالتقاط."

    def _run_capture(self, iface: str) -> None:
        assert self._app is not None
        bpf = get_setting("capture_bpf_filter", "tcp or udp or icmp") or "tcp or udp or icmp"

        def _handler(pkt):
            if self._stop.is_set():
                return
            try:
                meta = self._extract(pkt)
                if not meta:
                    return
                now = time.time()
                self._pps_window = [t for t in self._pps_window if now - t < 1.0]
                self._pps_window.append(now)
                self.packets_per_second = float(len(self._pps_window))
                with self._buffer_lock:
                    self._packet_buffer.append(meta)
                if time.time() - self._last_flush > 2.0 or len(self._packet_buffer) >= 50:
                    self._flush(self._app)
            except Exception as exc:  # noqa: BLE001
                self.runtime_error = str(exc)

        try:
            sniff(
                iface=iface if iface else None,
                filter=bpf,
                prn=_handler,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
            )
        except PermissionError as exc:
            self.runtime_error = f"لا توجد صلاحية للالتقاط: {exc}"
            self._update_sensor(
                self._app, status="no_permission", error=self.runtime_error, active=False
            )
        except Exception as exc:  # noqa: BLE001
            self.runtime_error = str(exc)
            self._update_sensor(
                self._app, status="error", error=self.runtime_error, active=False
            )

    def _extract(self, pkt) -> Optional[dict]:
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        protocol = "IP"
        src_port = dst_port = None
        flags = None
        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
        return {
            "observed_at": datetime.now(timezone.utc),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "byte_count": len(pkt),
            "flags": flags,
            "source_type": "scapy",
            "is_simulated": False,
        }

    def _flush(self, app: Flask) -> None:
        with self._buffer_lock:
            batch = list(self._packet_buffer)
            self._packet_buffer.clear()
            self._last_flush = time.time()
        if not batch:
            return
        with app.app_context():
            sensor = Sensor.query.first()
            sensor_id = sensor.id if sensor else None
            total_bytes = 0
            from app.detection.engine import DetectionEngine

            engine = DetectionEngine()
            for meta in batch:
                total_bytes += meta.get("byte_count") or 0
                ev = NetworkEvent(
                    observed_at=meta["observed_at"],
                    src_ip=meta.get("src_ip"),
                    dst_ip=meta.get("dst_ip"),
                    src_port=meta.get("src_port"),
                    dst_port=meta.get("dst_port"),
                    protocol=meta.get("protocol"),
                    packet_count=1,
                    byte_count=meta.get("byte_count") or 0,
                    flags=meta.get("flags"),
                    source_type="scapy",
                    is_simulated=False,
                    sensor_id=sensor_id,
                )
                db.session.add(ev)
                meta["sensor_id"] = sensor_id
                try:
                    engine.process_packet_meta(meta)
                except Exception:
                    pass
            if sensor:
                sensor.packets_captured = (sensor.packets_captured or 0) + len(batch)
                sensor.bytes_captured = (sensor.bytes_captured or 0) + total_bytes
                sensor.last_activity = datetime.now(timezone.utc)
                sensor.capture_active = True
                sensor.status = "running"
            db.session.commit()

    def _update_sensor(
        self,
        app: Flask,
        status: str,
        error: Optional[str] = None,
        active: bool = False,
        interface: Optional[str] = None,
    ) -> None:
        with app.app_context():
            sensor = Sensor.query.first()
            if not sensor:
                sensor = Sensor(name="المستشعر المحلي", hostname=socket.gethostname())
                db.session.add(sensor)
            sensor.status = status
            sensor.capture_active = active
            sensor.last_error = error
            if interface:
                sensor.interface = interface
            if active:
                sensor.last_activity = datetime.now(timezone.utc)
            db.session.commit()


capture_manager = CaptureManager()
