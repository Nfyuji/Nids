"""إدارة المستشعرات."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import login_required

from app.integrations.scapy_sensor import capture_manager
from app.integrations.suricata_eve import suricata_reader
from app.models.sensor import Sensor
from app.routes.decorators import role_required
from app.services.audit import log_action

sensors_bp = Blueprint("sensors", __name__)


@sensors_bp.route("/")
@login_required
def list_sensors():
    sensors = Sensor.query.all()
    return render_template(
        "sensors.html",
        sensors=sensors,
        scapy=capture_manager.scapy_status(),
        suricata=suricata_reader.status(),
        pps=capture_manager.packets_per_second,
    )


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
