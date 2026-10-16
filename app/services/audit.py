"""تسجيل عمليات التدقيق."""
from __future__ import annotations

from flask import request
from flask_login import current_user

from app.models import db
from app.models.settings import AuditLog


def log_action(action: str, target_type: str | None = None, target_id=None, details: str | None = None):
    user_id = current_user.id if current_user and current_user.is_authenticated else None
    ip = request.remote_addr if request else None
    entry = AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        details=details,
        ip_address=ip,
    )
    db.session.add(entry)
    db.session.commit()
