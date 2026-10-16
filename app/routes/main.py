"""الصفحات الرئيسية."""
from __future__ import annotations

from flask import Blueprint, render_template, request
from flask_login import current_user, login_required

from app.integrations.scapy_sensor import capture_manager
from app.integrations.suricata_eve import suricata_reader
from app.models.detection import DetectionRule
from app.models.sensor import Sensor
from app.services import stats as stats_service

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def landing():
    """الصفحة الرئيسية العامة."""
    return render_template("landing.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    data = stats_service.dashboard_stats()
    timeline = stats_service.traffic_timeline(24)
    distribution = stats_service.attack_distribution()
    recent = stats_service.recent_alerts(10)
    offenders = stats_service.top_offenders(8)
    modules = stats_service.detection_modules_status()
    sensor = Sensor.query.first()
    # قوائم منفصلة لتجنب تعارض Jinja مع dict.items / السمات
    attack_categories = list(distribution.get("categories") or [])
    return render_template(
        "dashboard.html",
        stats=data,
        timeline=timeline,
        distribution=distribution,
        attack_categories=attack_categories,
        distribution_has_data=bool(distribution.get("has_data")),
        timeline_has_data=bool(timeline.get("has_data")),
        recent_alerts=recent,
        offenders=offenders,
        modules=modules,
        sensor=sensor,
        scapy=capture_manager.scapy_status(),
        suricata=suricata_reader.status(),
    )


@main_bp.route("/live-traffic")
@login_required
def live_traffic():
    from app.models.network_event import NetworkEvent

    events = (
        NetworkEvent.query.filter_by(is_simulated=False)
        .order_by(NetworkEvent.observed_at.desc())
        .limit(100)
        .all()
    )
    sensor = Sensor.query.first()
    scapy = capture_manager.scapy_status()
    return render_template(
        "live_traffic.html",
        events=events,
        sensor=sensor,
        scapy=scapy,
        pps=capture_manager.packets_per_second,
    )


@main_bp.route("/attack-analysis")
@login_required
def attack_analysis():
    distribution = stats_service.attack_distribution()
    timeline = stats_service.traffic_timeline(24)
    offenders = stats_service.top_offenders(15)
    recent = stats_service.recent_alerts(20)
    return render_template(
        "attack_analysis.html",
        distribution=distribution,
        timeline=timeline,
        distribution_has_data=bool(distribution.get("has_data")),
        timeline_has_data=bool(timeline.get("has_data")),
        offenders=offenders,
        recent_alerts=recent,
    )


@main_bp.route("/ip-investigation", methods=["GET", "POST"])
@login_required
def ip_investigation():
    from flask import flash, redirect, url_for
    from flask_login import current_user

    from app.services.local_network import get_lan_profile, import_arp_as_events

    if request.method == "POST" and request.form.get("action") == "discover_lan":
        if current_user.role not in ("admin", "analyst"):
            flash("صلاحية غير كافية لاكتشاف الشبكة.", "danger")
            return redirect(url_for("main.ip_investigation"))
        try:
            discovered = import_arp_as_events()
            flash(
                f"تم اكتشاف الشبكة المحلية: {discovered['hosts_seen']} جهاز / "
                f"استيراد {discovered['imported']} حدث.",
                "success",
            )
        except Exception as exc:  # noqa: BLE001
            flash(f"تعذر الاكتشاف: {exc}", "danger")
        ip_post = (request.form.get("ip") or "").strip()
        if ip_post:
            return redirect(url_for("main.ip_investigation", ip=ip_post))
        return redirect(url_for("main.ip_investigation"))

    ip = (request.args.get("ip") or "").strip()
    result = stats_service.ip_investigation(ip) if ip else None
    sensor = Sensor.query.first()
    lan = get_lan_profile()
    return render_template(
        "ip_investigation.html",
        ip=ip,
        result=result,
        sensor=sensor,
        scapy=capture_manager.scapy_status(),
        lan=lan,
    )


@main_bp.route("/attack-types")
@login_required
def attack_types():
    rules = DetectionRule.query.order_by(DetectionRule.id).all()
    return render_template("attack_types.html", rules=rules)


@main_bp.context_processor
def inject_globals():
    theme = "light"
    if current_user.is_authenticated:
        theme = current_user.theme_preference or "light"
    unread = 0
    try:
        from app.models.alert import Alert

        unread = Alert.query.filter_by(is_simulated=False, status="new").count()
    except Exception:
        pass
    return {"ui_theme": theme, "alert_badge_count": unread}
