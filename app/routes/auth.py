"""المصادقة."""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length

from app.models import db
from app.models.user import User
from app.services.audit import log_action

auth_bp = Blueprint("auth", __name__)


class LoginForm(FlaskForm):
    username = StringField("اسم المستخدم", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("كلمة المرور", validators=[DataRequired()])
    submit = SubmitField("تسجيل الدخول")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and user.is_active and user.check_password(form.password.data):
            login_user(user)
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            log_action("login", target_type="user", target_id=user.id)
            next_url = request.args.get("next") or url_for("main.dashboard")
            return redirect(next_url)
        flash("بيانات الدخول غير صحيحة.", "danger")
    return render_template("login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log_action("logout", target_type="user", target_id=current_user.id)
    logout_user()
    flash("تم تسجيل الخروج.", "info")
    return redirect(url_for("main.landing"))
