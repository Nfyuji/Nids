"""استيراد سجلات مصادقة اختيارية لكشف القوة الغاشمة."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from app.detection.engine import DetectionEngine

# أمثلة سجلات آمنة للاختبار — لا تنفّذ هجمات حقيقية
SSH_FAIL_RE = re.compile(
    r"(?P<ts>\w+\s+\d+\s+[\d:]+)?.*Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+)"
)


def parse_ssh_line(line: str, default_time: datetime | None = None) -> dict | None:
    m = SSH_FAIL_RE.search(line)
    if not m:
        return None
    return {
        "src_ip": m.group("ip"),
        "username": m.group("user"),
        "success": False,
        "auth_result": "failure",
        "service": "ssh",
        "protocol": "SSH",
        "observed_at": default_time or datetime.now(timezone.utc),
        "source_type": "auth_log",
        "is_simulated": "SIMULATED" in line.upper() or "TEST" in line.upper(),
    }


def import_auth_log_file(path: str, mark_simulated: bool = False) -> int:
    """يستورد ملف سجلات محلي آمن ويعيد عدد التنبيهات المُنشأة."""
    p = Path(path)
    if not p.is_file():
        return 0
    engine = DetectionEngine()
    created = 0
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        event = parse_ssh_line(line)
        if not event:
            continue
        if mark_simulated:
            event["is_simulated"] = True
        alerts = engine.process_auth_failure(event)
        created += len(alerts)
    return created
