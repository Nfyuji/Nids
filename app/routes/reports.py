"""التقارير."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, render_template, request
from flask_login import login_required
from sqlalchemy import func

from app.models import db
from app.models.alert import Alert
from app.models.network_event import NetworkEvent
from app.models.sensor import Sensor
from app.services.audit import log_action
from app.services import stats as stats_service

reports_bp = Blueprint("reports", __name__)


def _period_days() -> int:
    try:
        return max(1, min(90, int(request.args.get("days", 7))))
    except ValueError:
        return 7


@reports_bp.route("/")
@login_required
def reports_page():
    days = _period_days()
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = Alert.query.filter(Alert.is_simulated.is_(False), Alert.observed_at >= since)
    total = q.count()
    by_sev = dict(
        db.session.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.is_simulated.is_(False), Alert.observed_at >= since)
        .group_by(Alert.severity)
        .all()
    )
    by_type = dict(
        db.session.query(Alert.attack_type, func.count(Alert.id))
        .filter(Alert.is_simulated.is_(False), Alert.observed_at >= since)
        .group_by(Alert.attack_type)
        .all()
    )
    offenders = stats_service.top_offenders(10)
    sensor = Sensor.query.first()
    traffic = (
        db.session.query(func.coalesce(func.sum(NetworkEvent.packet_count), 0))
        .filter(NetworkEvent.is_simulated.is_(False), NetworkEvent.observed_at >= since)
        .scalar()
        or 0
    )
    limitations = [
        "الإحصائيات لا تشمل البيانات التجريبية (is_simulated).",
        "تكامل Suricata اختياري ويتطلب مسار EVE JSON صالحاً.",
        "التقاط Scapy يتطلب Npcap وصلاحيات مناسبة على Windows.",
        "كشف القوة الغاشمة يعتمد على سجلات مصادقة موثّقة وليس حزم TCP وحدها.",
    ]
    return render_template(
        "reports.html",
        days=days,
        total=total,
        by_sev=by_sev,
        by_type=by_type,
        offenders=offenders,
        sensor=sensor,
        traffic_packets=int(traffic),
        limitations=limitations,
        has_data=total > 0 or int(traffic) > 0,
    )


@reports_bp.route("/export.csv")
@login_required
def export_report_csv():
    days = _period_days()
    since = datetime.now(timezone.utc) - timedelta(days=days)
    alerts = (
        Alert.query.filter(Alert.is_simulated.is_(False), Alert.observed_at >= since)
        .order_by(Alert.observed_at.desc())
        .all()
    )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["report_period_days", days])
    w.writerow([])
    w.writerow(
        ["id", "observed_at", "attack_type", "severity", "src_ip", "dst_ip", "rule", "source"]
    )
    for a in alerts:
        w.writerow(
            [
                a.id,
                a.observed_at.isoformat() if a.observed_at else "",
                a.attack_type,
                a.severity,
                a.src_ip,
                a.dst_ip,
                a.detection_rule,
                a.source_type,
            ]
        )
    log_action("export_report_csv", details=f"days={days};count={len(alerts)}")
    return Response(
        "\ufeff" + buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=nids_report.csv"},
    )


@reports_bp.route("/export.pdf")
@login_required
def export_report_pdf():
    """تقرير PDF بسيط عند توفر reportlab."""
    days = _period_days()
    since = datetime.now(timezone.utc) - timedelta(days=days)
    total = Alert.query.filter(
        Alert.is_simulated.is_(False), Alert.observed_at >= since
    ).count()
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        return Response(
            "مكتبة reportlab غير مثبتة. استخدم تصدير CSV.",
            status=503,
            mimetype="text/plain; charset=utf-8",
        )

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    c.setFont("Helvetica", 14)
    c.drawString(50, height - 50, "NIDS Security Report")
    c.setFont("Helvetica", 11)
    c.drawString(50, height - 80, f"Period (days): {days}")
    c.drawString(50, height - 100, f"Real alerts: {total}")
    c.drawString(
        50,
        height - 120,
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
    )
    c.drawString(50, height - 150, "Note: Simulated data excluded.")
    c.showPage()
    c.save()
    buf.seek(0)
    log_action("export_report_pdf", details=f"days={days}")
    return Response(
        buf.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=nids_report.pdf"},
    )
