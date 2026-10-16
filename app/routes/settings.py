"""صفحة الإعدادات."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.models import db
from app.models.detection import DetectionRule
from app.models.user import User
from app.routes.decorators import role_required
from app.services.audit import log_action
from app.services.settings_service import get_all_settings, set_setting

settings_bp = Blueprint("settings", __name__)

INT_KEYS = {
    "log_retention_days",
    "port_scan_threshold",
    "port_scan_window_seconds",
    "dos_pps_threshold",
    "dos_syn_threshold",
    "dos_window_seconds",
    "brute_force_threshold",
    "brute_force_window_seconds",
    "alert_dedup_seconds",
}


@settings_bp.route("/", methods=["GET", "POST"])
@login_required
@role_required("admin")
def settings_page():
    if request.method == "POST":
        action = request.form.get("action", "save_settings")
        if action == "save_settings":
            for key in [
                "capture_interface",
                "capture_bpf_filter",
                "suricata_eve_path",
                "timezone",
                "exclude_ips",
                "theme_default",
                *INT_KEYS,
            ]:
                if key not in request.form:
                    continue
                raw = request.form.get(key, "").strip()
                if key in INT_KEYS:
                    try:
                        val = int(raw)
                        if val < 0:
                            raise ValueError
                    except ValueError:
                        flash(f"قيمة غير صالحة للحقل: {key}", "danger")
                        return redirect(url_for("settings.settings_page"))
                    set_setting(key, val)
                else:
                    set_setting(key, raw)
            log_action("settings_update")
            flash("تم حفظ الإعدادات بعد التحقق.", "success")
        elif action == "toggle_rule":
            rule_id = request.form.get("rule_id")
            rule = db.session.get(DetectionRule, int(rule_id))
            if rule:
                rule.enabled = not rule.enabled
                rule.status = "active" if rule.enabled else "disabled"
                db.session.commit()
                log_action("toggle_rule", target_type="rule", target_id=rule.id)
                flash(f"تم تحديث قاعدة {rule.name_ar}.", "success")
        elif action == "theme":
            theme = request.form.get("theme", "dark")
            if theme not in ("dark", "light"):
                flash("سمة غير صالحة.", "danger")
            else:
                current_user.theme_preference = theme
                db.session.commit()
                flash("تم تحديث السمة.", "success")
        elif action == "change_password":
            new_pass = request.form.get("new_password") or ""
            if len(new_pass) < 8:
                flash("كلمة المرور يجب ألا تقل عن 8 أحرف.", "danger")
            else:
                current_user.set_password(new_pass)
                db.session.commit()
                log_action("password_change", target_type="user", target_id=current_user.id)
                flash("تم تغيير كلمة المرور.", "success")
        return redirect(url_for("settings.settings_page"))

    settings = get_all_settings()
    rules = DetectionRule.query.order_by(DetectionRule.id).all()
    users = User.query.order_by(User.id).all()
    return render_template(
        "settings.html", settings=settings, rules=rules, users=users
    )


@settings_bp.route("/theme", methods=["POST"])
@login_required
def set_theme():
    theme = request.form.get("theme", "dark")
    if theme in ("dark", "light"):
        current_user.theme_preference = theme
        db.session.commit()
    return redirect(request.referrer or url_for("main.dashboard"))
