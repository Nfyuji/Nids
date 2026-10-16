"""واجهات REST داخلية."""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import login_required

from app.integrations.scapy_sensor import capture_manager
from app.integrations.suricata_eve import suricata_reader
from app.models.network_event import NetworkEvent
from app.models.sensor import Sensor
from app.services import stats as stats_service

api_bp = Blueprint("api", __name__)


@api_bp.route("/stats")
@login_required
def api_stats():
    return jsonify(stats_service.dashboard_stats())


@api_bp.route("/timeline")
@login_required
def api_timeline():
    hours = int(request.args.get("hours", 24))
    return jsonify(stats_service.traffic_timeline(hours))


@api_bp.route("/distribution")
@login_required
def api_distribution():
    return jsonify(stats_service.attack_distribution())


@api_bp.route("/alerts/recent")
@login_required
def api_recent_alerts():
    limit = min(50, int(request.args.get("limit", 10)))
    alerts = stats_service.recent_alerts(limit)
    return jsonify([a.to_dict() for a in alerts])


@api_bp.route("/traffic/live")
@login_required
def api_live_traffic():
    events = (
        NetworkEvent.query.filter_by(is_simulated=False)
        .order_by(NetworkEvent.observed_at.desc())
        .limit(50)
        .all()
    )
    sensor = Sensor.query.first()
    scapy = capture_manager.scapy_status()
    return jsonify(
        {
            "events": [e.to_dict() for e in events],
            "pps": capture_manager.packets_per_second,
            "sensor": sensor.to_dict() if sensor else None,
            "scapy": scapy,
            "capture_active": bool(sensor and sensor.capture_active),
        }
    )


@api_bp.route("/sensors/status")
@login_required
def api_sensors():
    sensors = Sensor.query.all()
    return jsonify(
        {
            "sensors": [s.to_dict() for s in sensors],
            "scapy": capture_manager.scapy_status(),
            "suricata": suricata_reader.status(),
        }
    )


@api_bp.route("/ip/<path:ip>")
@login_required
def api_ip(ip: str):
    return jsonify(stats_service.ip_investigation(ip))


@api_bp.route("/network-map")
@login_required
def api_network_map():
    from app.services.network_map import build_network_map

    return jsonify(build_network_map())
