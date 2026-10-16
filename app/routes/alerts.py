"""صفحات وإدارة التنبيهات."""
from __future__ import annotations

import csv
import io
from datetime import datetime

from flask import (
    Blueprint,
    Response,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import or_

from app.models import db
from app.models.alert import Alert, InvestigationNote, STATUSES
from app.routes.decorators import role_required
from app.services.alert_service import update_status
from app.services.audit import log_action

alerts_bp = Blueprint("alerts", __name__)


def _filtered_query():
    q = Alert.query
    include_sim = request.args.get("include_simulated") == "1"
    if not include_sim:
        q = q.filter_by(is_simulated=False)

    search = (request.args.get("q") or "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(
            or_(
                Alert.title.ilike(like),
                Alert.src_ip.ilike(like),
                Alert.dst_ip.ilike(like),
                Alert.detection_rule.ilike(like),
                Alert.description.ilike(like),
            )
        )
    attack_type = request.args.get("attack_type")
    if attack_type:
        q = q.filter_by(attack_type=attack_type)
    severity = request.args.get("severity")
    if severity:
        q = q.filter_by(severity=severity)
    source_type = request.args.get("source_type")
    if source_type:
        q = q.filter_by(source_type=source_type)
    ip = (request.args.get("ip") or "").strip()
    if ip:
        q = q.filter(or_(Alert.src_ip == ip, Alert.dst_ip == ip))
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    if date_from:
        try:
            q = q.filter(Alert.observed_at >= datetime.fromisoformat(date_from))
        except ValueError:
            pass
    if date_to:
        try:
            q = q.filter(Alert.observed_at <= datetime.fromisoformat(date_to))
        except ValueError:
            pass
    return q.order_by(Alert.observed_at.desc())


@alerts_bp.route("/")
@login_required
def list_alerts():
    page = max(1, int(request.args.get("page", 1)))
    per_page = 25
    pagination = _filtered_query().paginate(page=page, per_page=per_page, error_out=False)
    return render_template(
        "alerts.html",
        pagination=pagination,
        alerts=pagination.items,
        statuses=STATUSES,
        filters=request.args,
    )


@alerts_bp.route("/<int:alert_id>")
@login_required
def alert_details(alert_id: int):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        flash("التنبيه غير موجود.", "warning")
        return redirect(url_for("alerts.list_alerts"))
    notes = (
        InvestigationNote.query.filter_by(alert_id=alert.id)
        .order_by(InvestigationNote.created_at.desc())
        .all()
    )
    return render_template(
        "alert_details.html", alert=alert, notes=notes, statuses=STATUSES
    )


@alerts_bp.route("/<int:alert_id>/status", methods=["POST"])
@login_required
@role_required("admin", "analyst")
def change_status(alert_id: int):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        flash("التنبيه غير موجود.", "warning")
        return redirect(url_for("alerts.list_alerts"))
    new_status = request.form.get("status")
    note = (request.form.get("note") or "").strip()
    if new_status not in STATUSES:
        flash("حالة غير صالحة.", "danger")
        return redirect(url_for("alerts.alert_details", alert_id=alert_id))
    update_status(alert, new_status, current_user.id, note or None)
    log_action(
        "alert_status_change",
        target_type="alert",
        target_id=alert.id,
        details=f"{alert.status}",
    )
    flash("تم تحديث حالة التحقيق مع تسجيل التعديل.", "success")
    return redirect(url_for("alerts.alert_details", alert_id=alert_id))


@alerts_bp.route("/export.csv")
@login_required
def export_csv():
    rows = _filtered_query().limit(5000).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "id",
            "observed_at",
            "attack_type",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "severity",
            "detection_rule",
            "source_type",
            "is_simulated",
            "status",
            "title",
        ]
    )
    for a in rows:
        writer.writerow(
            [
                a.id,
                a.observed_at.isoformat() if a.observed_at else "",
                a.attack_type,
                a.src_ip,
                a.dst_ip,
                a.src_port,
                a.dst_port,
                a.protocol,
                a.severity,
                a.detection_rule,
                a.source_type,
                a.is_simulated,
                a.status,
                a.title,
            ]
        )
    log_action("export_alerts_csv", details=f"count={len(rows)}")
    return Response(
        "\ufeff" + buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=nids_alerts.csv"},
    )
