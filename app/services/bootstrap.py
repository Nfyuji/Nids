"""تهيئة البيانات الافتراضية عند أول تشغيل."""
from __future__ import annotations

import secrets
import socket
from datetime import datetime, timezone

from flask import current_app

from app.models import db
from app.models.detection import DetectionRule
from app.models.sensor import Sensor
from app.models.settings import ApplicationSetting, AuditLog
from app.models.user import User


DEFAULT_RULES = [
    {
        "rule_key": "port_scan",
        "name_ar": "فحص المنافذ",
        "name_en": "Port Scanning",
        "category": "port_scan",
        "enabled": True,
        "status": "active",
        "threshold": 20,
        "window_seconds": 60,
        "description": "رصد اتصالات مصدر واحد إلى منافذ وجهة متعددة خلال نافذة زمنية.",
        "requires_source": "scapy",
    },
    {
        "rule_key": "brute_force",
        "name_ar": "القوة الغاشمة",
        "name_en": "Brute Force",
        "category": "brute_force",
        "enabled": True,
        "status": "needs_data",
        "threshold": 5,
        "window_seconds": 300,
        "description": "يتطلب سجلات مصادقة (SSH / Windows / VPN). لا يُستنتج من حزم TCP وحدها.",
        "requires_source": "auth_log",
    },
    {
        "rule_key": "dos_ddos",
        "name_ar": "رفض الخدمة",
        "name_en": "DoS / DDoS",
        "category": "dos",
        "enabled": True,
        "status": "active",
        "threshold": 500,
        "window_seconds": 10,
        "description": "مؤشرات ارتفاع معدل الحزم أو SYN. لا يؤكد DDoS من مصدر واحد فقط.",
        "requires_source": "scapy",
    },
    {
        "rule_key": "malware_traffic",
        "name_ar": "حركة برمجيات خبيثة",
        "name_en": "Malware Traffic",
        "category": "malware",
        "enabled": True,
        "status": "needs_data",
        "threshold": None,
        "window_seconds": None,
        "description": "يعتمد على قواعد Suricata ومؤشرات محلية قابلة للتحديث.",
        "requires_source": "suricata_or_ioc",
    },
    {
        "rule_key": "suspicious_connections",
        "name_ar": "اتصالات مشبوهة",
        "name_en": "Suspicious Connections",
        "category": "suspicious",
        "enabled": True,
        "status": "active",
        "threshold": 10,
        "window_seconds": 300,
        "description": "اتصالات غير معتادة أو منافذ حساسة أو وجهات في قائمة مؤشرات محلية.",
        "requires_source": "scapy",
    },
]

DEFAULT_SETTINGS = [
    ("capture_interface", "", "string", "واجهة الشبكة للمراقبة"),
    ("capture_bpf_filter", "tcp or udp or icmp", "string", "مرشح BPF"),
    ("suricata_eve_path", "", "string", "مسار ملف Suricata EVE JSON"),
    ("timezone", "Asia/Riyadh", "string", "المنطقة الزمنية"),
    ("log_retention_days", "30", "int", "مدة الاحتفاظ بالسجلات بالأيام"),
    ("port_scan_threshold", "20", "int", "عتبة فحص المنافذ"),
    ("port_scan_window_seconds", "60", "int", "نافذة فحص المنافذ بالثواني"),
    ("dos_pps_threshold", "500", "int", "عتبة الحزم/ثانية لـ DoS"),
    ("dos_syn_threshold", "200", "int", "عتبة SYN لـ DoS"),
    ("dos_window_seconds", "10", "int", "نافذة DoS بالثواني"),
    ("brute_force_threshold", "5", "int", "عتبة القوة الغاشمة"),
    ("brute_force_window_seconds", "300", "int", "نافذة القوة الغاشمة"),
    ("alert_dedup_seconds", "120", "int", "نافذة منع تكرار التنبيهات"),
    ("theme_default", "light", "string", "السمة الافتراضية"),
    ("exclude_ips", "127.0.0.1,::1", "string", "عناوين IP مستثناة من الكشف"),
]


def ensure_defaults(app) -> None:
    _ensure_admin(app)
    _ensure_sensor()
    _ensure_rules(app)
    _ensure_settings(app)


def _ensure_admin(app) -> None:
    if User.query.count() > 0:
        return
    password = app.config.get("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    username = app.config.get("ADMIN_USERNAME", "admin")
    email = app.config.get("ADMIN_EMAIL", "admin@localhost")
    user = User(
        username=username,
        email=email,
        role="admin",
        display_name="المسؤول",
        theme_preference=app.config.get("THEME_DEFAULT", "light"),
    )
    user.set_password(password)
    db.session.add(user)
    db.session.add(
        AuditLog(
            action="bootstrap_admin",
            details="تم إنشاء حساب المسؤول الأولي",
            created_at=datetime.now(timezone.utc),
        )
    )
    db.session.commit()
    # طباعة كلمة المرور مرة واحدة فقط عند الإنشاء التلقائي
    if not app.config.get("ADMIN_PASSWORD"):
        print(f"[NIDS] تم إنشاء المسؤول '{username}' — كلمة المرور المؤقتة: {password}")
        print("[NIDS] غيّر كلمة المرور فورًا من الإعدادات أو عبر متغير ADMIN_PASSWORD.")


def _ensure_sensor() -> None:
    if Sensor.query.count() > 0:
        return
    hostname = socket.gethostname()
    sensor = Sensor(
        name="المستشعر المحلي",
        hostname=hostname,
        interface="",
        status="standby",
        capture_active=False,
    )
    db.session.add(sensor)
    db.session.commit()


def _ensure_rules(app) -> None:
    for rule in DEFAULT_RULES:
        existing = DetectionRule.query.filter_by(rule_key=rule["rule_key"]).first()
        if existing:
            continue
        if rule["rule_key"] == "port_scan":
            rule = {**rule, "threshold": app.config.get("PORT_SCAN_THRESHOLD", 20)}
        db.session.add(DetectionRule(**rule))
    db.session.commit()


def _ensure_settings(app) -> None:
    mapping = {
        "capture_interface": app.config.get("CAPTURE_INTERFACE", ""),
        "capture_bpf_filter": app.config.get("CAPTURE_BPF_FILTER", "tcp or udp or icmp"),
        "suricata_eve_path": app.config.get("SURICATA_EVE_PATH", ""),
        "timezone": app.config.get("TIMEZONE", "Asia/Riyadh"),
        "log_retention_days": str(app.config.get("LOG_RETENTION_DAYS", 30)),
        "port_scan_threshold": str(app.config.get("PORT_SCAN_THRESHOLD", 20)),
        "port_scan_window_seconds": str(app.config.get("PORT_SCAN_WINDOW_SECONDS", 60)),
        "dos_pps_threshold": str(app.config.get("DOS_PPS_THRESHOLD", 500)),
        "dos_syn_threshold": str(app.config.get("DOS_SYN_THRESHOLD", 200)),
        "dos_window_seconds": str(app.config.get("DOS_WINDOW_SECONDS", 10)),
        "brute_force_threshold": str(app.config.get("BRUTE_FORCE_THRESHOLD", 5)),
        "brute_force_window_seconds": str(app.config.get("BRUTE_FORCE_WINDOW_SECONDS", 300)),
        "alert_dedup_seconds": str(app.config.get("ALERT_DEDUP_SECONDS", 120)),
        "theme_default": app.config.get("THEME_DEFAULT", "light"),
    }
    for key, value, vtype, desc in DEFAULT_SETTINGS:
        if ApplicationSetting.query.filter_by(key=key).first():
            continue
        db.session.add(
            ApplicationSetting(
                key=key,
                value=mapping.get(key, value),
                value_type=vtype,
                description=desc,
            )
        )
    db.session.commit()
