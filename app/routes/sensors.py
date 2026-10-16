"""إدارة المستشعرات."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import login_required

from app.integrations.scapy_sensor import capture_manager
from app.integrations.suricata_eve import suricata_reader
from app.models.sensor import Sensor
from app.routes.decorators import role_required
from app.services.audit import log_action
from app.services.demo_scenario import clear_demo_data, run_graduation_demo
from app.services.local_network import get_lan_profile, import_arp_as_events
from app.services.settings_service import get_setting

sensors_bp = Blueprint("sensors", __name__)


@sensors_bp.route("/")
@login_required
def list_sensors():
    sensors = Sensor.query.all()
    try:
        lan = get_lan_profile()
    except Exception:  # noqa: BLE001
        lan = {"hostname": "—", "local_ips": [], "gateway": None}
    return render_template(
        "sensors.html",
        sensors=sensors,
        scapy=capture_manager.scapy_status(),
        suricata=suricata_reader.status(),
        pps=capture_manager.packets_per_second,
        lan=lan,
        demo_mode=bool(get_setting("demo_mode", False)),
    )


@sensors_bp.route("/demo/start", methods=["POST"])
@login_required
@role_required("admin", "analyst")
def start_demo():
    """تشغيل سيناريو عرض التخرج (بيانات تجريبية معلّمة)."""
    try:
        result = run_graduation_demo()
        log_action("demo_start", details=str(result))
        flash(
            f"تم تشغيل سيناريو التخرج: {result['alerts']} تنبيهاً و {result['events']} حدثاً تجريبياً. "
            f"المهاجم التجريبي: {result['attacker']} — افتح لوحة التحكم.",
            "success",
        )
    except Exception as exc:  # noqa: BLE001
        flash(f"تعذر تشغيل العرض: {exc}", "danger")
    return redirect(url_for("main.dashboard"))


@sensors_bp.route("/demo/clear", methods=["POST"])
@login_required
@role_required("admin")
def clear_demo():
    try:
        result = clear_demo_data()
        log_action("demo_clear", details=str(result))
        flash(
            f"تم مسح بيانات العرض ({result['deleted_alerts']} تنبيه / {result['deleted_events']} حدث).",
            "info",
        )
    except Exception as exc:  # noqa: BLE001
        flash(f"تعذر المسح: {exc}", "danger")
    return redirect(url_for("sensors.list_sensors"))


@sensors_bp.route("/discover-lan", methods=["POST"])
@login_required
@role_required("admin", "analyst")
def discover_lan():
    """اكتشاف أجهزة الشبكة المحلية عبر جدول ARP فقط (بدون إنترنت)."""
    try:
        result = import_arp_as_events()
        log_action(
            "lan_discover",
            details=f"imported={result['imported']};hosts={result['hosts_seen']}",
        )
        flash(
            f"تم رصد {result['hosts_seen']} جهازاً على الشبكة المحلية واستيراد {result['imported']} حدثاً. "
            f"البوابة: {result.get('gateway') or '—'}",
            "success",
        )
    except Exception as exc:  # noqa: BLE001
        flash(f"تعذر اكتشاف الشبكة المحلية: {exc}", "danger")
    return redirect(url_for("sensors.list_sensors"))


@sensors_bp.route("/start", methods=["POST"])
@login_required
@role_required("admin")
def start_capture():
    from flask import current_app

    ok, msg = capture_manager.start(current_app._get_current_object())
    log_action("capture_start", details=msg)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("sensors.list_sensors"))


@sensors_bp.route("/stop", methods=["POST"])
@login_required
@role_required("admin")
def stop_capture():
    from flask import current_app

    ok, msg = capture_manager.stop(current_app._get_current_object())
    log_action("capture_stop", details=msg)
    flash(msg, "success" if ok else "warning")
    return redirect(url_for("sensors.list_sensors"))


@sensors_bp.route("/suricata/start", methods=["POST"])
@login_required
@role_required("admin")
def start_suricata():
    from flask import current_app

    ok, msg = suricata_reader.start(current_app._get_current_object())
    log_action("suricata_start", details=msg)
    flash(msg, "success" if ok else "warning")
    return redirect(url_for("sensors.list_sensors"))


@sensors_bp.route("/suricata/stop", methods=["POST"])
@login_required
@role_required("admin")
def stop_suricata():
    from flask import current_app

    ok, msg = suricata_reader.stop(current_app._get_current_object())
    log_action("suricata_stop", details=msg)
    flash(msg, "info")
    return redirect(url_for("sensors.list_sensors"))
