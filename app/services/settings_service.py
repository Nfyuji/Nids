"""إدارة إعدادات التطبيق."""
from __future__ import annotations

from app.models import db
from app.models.settings import ApplicationSetting


def get_setting(key: str, default=None):
    row = ApplicationSetting.query.filter_by(key=key).first()
    if not row:
        return default
    return row.typed_value()


def get_all_settings() -> dict:
    return {s.key: s.typed_value() for s in ApplicationSetting.query.all()}


def set_setting(key: str, value, value_type: str | None = None) -> ApplicationSetting:
    row = ApplicationSetting.query.filter_by(key=key).first()
    if not row:
        row = ApplicationSetting(key=key, value_type=value_type or "string")
        db.session.add(row)
    if isinstance(value, bool):
        row.value = "true" if value else "false"
        row.value_type = "bool"
    elif isinstance(value, int) and not isinstance(value, bool):
        row.value = str(value)
        row.value_type = "int"
    elif isinstance(value, float):
        row.value = str(value)
        row.value_type = "float"
    else:
        row.value = "" if value is None else str(value)
        if value_type:
            row.value_type = value_type
    db.session.commit()
    return row


def get_exclude_ips() -> set[str]:
    raw = get_setting("exclude_ips", "127.0.0.1,::1") or ""
    return {p.strip() for p in raw.split(",") if p.strip()}
