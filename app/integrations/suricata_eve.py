"""تكامل Suricata عبر قراءة EVE JSON."""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import Flask

from app.models import db
from app.models.sensor import Sensor
from app.services.alert_service import create_alert
from app.services.settings_service import get_setting

SEVERITY_MAP = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}


class SuricataEveReader:
    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._app: Optional[Flask] = None
        self._offset = 0
        self._inode = None
        self.last_status = "idle"
        self.last_error: Optional[str] = None
        self.events_imported = 0

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict:
        path = get_setting("suricata_eve_path", "") or ""
        exists = bool(path and Path(path).is_file())
        return {
            "configured": bool(path),
            "path": path,
            "file_exists": exists,
            "running": self.is_running,
            "last_status": self.last_status,
            "last_error": self.last_error,
            "events_imported": self.events_imported,
            "hint": None
            if exists
            else (
                "حدّد مسار eve.json في الإعدادات بعد تثبيت Suricata وتشغيله."
                if path
                else "Suricata غير مهيأ. ثبّته وحدّد مسار EVE JSON من الإعدادات."
            ),
        }

    def start(self, app: Flask) -> tuple[bool, str]:
        path = get_setting("suricata_eve_path", "") or app.config.get("SURICATA_EVE_PATH") or ""
        if not path:
            self.last_status = "unconfigured"
            return False, "مسار Suricata EVE غير محدد."
        if not Path(path).is_file():
            self.last_status = "missing_file"
            self.last_error = f"الملف غير موجود: {path}"
            self._set_sensor_suricata(app, False)
            return False, self.last_error
        if self.is_running:
            return True, "قارئ Suricata يعمل بالفعل."
        self._app = app
        self._stop.clear()
        # ابدأ من نهاية الملف لتجنب إعادة استيراد السجلات القديمة
        try:
            st = os.stat(path)
            self._offset = st.st_size
            self._inode = getattr(st, "st_ino", None)
        except OSError as exc:
            self.last_error = str(exc)
            return False, str(exc)
        self._thread = threading.Thread(
            target=self._follow, args=(path,), name="nids-suricata", daemon=True
        )
        self._thread.start()
        self.last_status = "running"
        self._set_sensor_suricata(app, True)
        return True, "بدأ متابعة ملف Suricata EVE."

    def stop(self, app: Flask) -> tuple[bool, str]:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._thread = None
        self.last_status = "stopped"
        self._set_sensor_suricata(app, False)
        return True, "تم إيقاف متابعة Suricata."

    def import_file(self, app: Flask, path: str, from_start: bool = False) -> int:
        """استيراد دفعة واحدة — مفيد للاختبارات."""
        count = 0
        p = Path(path)
        if not p.is_file():
            return 0
        with app.app_context():
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                if not from_start:
                    fh.seek(0, os.SEEK_END)
                for line in fh:
                    if self._ingest_line(line):
                        count += 1
            db.session.commit()
        self.events_imported += count
        return count

    def _follow(self, path: str) -> None:
        assert self._app is not None
        while not self._stop.is_set():
            try:
                st = os.stat(path)
                inode = getattr(st, "st_ino", None)
                if self._inode is not None and inode is not None and inode != self._inode:
                    self._offset = 0
                    self._inode = inode
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(self._offset)
                    while not self._stop.is_set():
                        line = fh.readline()
                        if not line:
                            self._offset = fh.tell()
                            time.sleep(0.5)
                            break
                        with self._app.app_context():
                            if self._ingest_line(line):
                                self.events_imported += 1
                                db.session.commit()
                        self._offset = fh.tell()
                self._set_sensor_suricata(self._app, True)
                self.last_status = "running"
                self.last_error = None
            except FileNotFoundError:
                self.last_status = "missing_file"
                self.last_error = "توقف الملف أو حُذف"
                self._set_sensor_suricata(self._app, False)
                time.sleep(2)
            except Exception as exc:  # noqa: BLE001
                self.last_status = "error"
                self.last_error = str(exc)
                self._set_sensor_suricata(self._app, False)
                time.sleep(2)

    def _ingest_line(self, line: str) -> bool:
        line = line.strip()
        if not line:
            return False
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return False
        if obj.get("event_type") != "alert":
            return False
        alert = obj.get("alert") or {}
        src = obj.get("src_ip")
        dst = obj.get("dest_ip")
        ts = obj.get("timestamp")
        observed = datetime.now(timezone.utc)
        if ts:
            try:
                observed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                pass
        severity = SEVERITY_MAP.get(alert.get("severity"), "medium")
        sid = str(alert.get("signature_id") or alert.get("signature") or "")
        signature = alert.get("signature") or "Suricata alert"
        category = (alert.get("category") or "suspicious").lower()
        attack_type = self._map_category(category, signature)

        created = create_alert(
            attack_type=attack_type,
            title=signature[:240],
            detection_rule=f"suricata:{sid or 'unknown'}",
            severity=severity,
            src_ip=src,
            dst_ip=dst,
            src_port=obj.get("src_port"),
            dst_port=obj.get("dest_port"),
            protocol=obj.get("proto"),
            description=f"تنبيه Suricata — الفئة: {alert.get('category')}",
            evidence={
                "signature": signature,
                "category": alert.get("category"),
                "gid": alert.get("gid"),
                "rev": alert.get("rev"),
                "raw_event_type": obj.get("event_type"),
            },
            confidence=0.8,
            source_type="suricata",
            is_simulated=False,
            observed_at=observed,
            external_sid=sid or None,
            dedup=True,
        )
        return created is not None

    @staticmethod
    def _map_category(category: str, signature: str) -> str:
        text = f"{category} {signature}".lower()
        if "scan" in text or "port" in text:
            return "port_scan"
        if "dos" in text or "ddos" in text or "flood" in text:
            return "dos"
        if "brute" in text or "password" in text or "auth" in text:
            return "brute_force"
        if "malware" in text or "trojan" in text or "c2" in text or "cnc" in text:
            return "malware"
        return "suspicious"

    def _set_sensor_suricata(self, app: Flask, connected: bool) -> None:
        with app.app_context():
            sensor = Sensor.query.first()
            if sensor:
                sensor.suricata_connected = connected
                if not connected and self.last_error:
                    sensor.last_error = self.last_error
                db.session.commit()


suricata_reader = SuricataEveReader()
