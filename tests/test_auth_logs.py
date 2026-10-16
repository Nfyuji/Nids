"""اختبار استيراد سجلات المصادقة."""
from app.detection.brute_force import reset_state
from app.integrations.auth_logs import import_auth_log_file, parse_ssh_line
from app.models.alert import Alert
from app.services.settings_service import set_setting


def test_parse_ssh_failure():
    line = "Jan 1 12:00:01 host sshd: Failed password for root from 203.0.113.8 port 22 ssh2"
    ev = parse_ssh_line(line)
    assert ev is not None
    assert ev["src_ip"] == "203.0.113.8"
    assert ev["username"] == "root"
    assert ev["success"] is False


def test_import_auth_log_marks_simulated(app, tmp_path):
    reset_state()
    log = tmp_path / "auth.log"
    lines = [
        "SIMULATED Failed password for admin from 198.51.100.20 port 22 ssh2",
        "SIMULATED Failed password for admin from 198.51.100.20 port 22 ssh2",
        "SIMULATED Failed password for admin from 198.51.100.20 port 22 ssh2",
        "SIMULATED Failed password for admin from 198.51.100.20 port 22 ssh2",
        "SIMULATED Failed password for admin from 198.51.100.20 port 22 ssh2",
    ]
    log.write_text("\n".join(lines), encoding="utf-8")
    with app.app_context():
        set_setting("brute_force_threshold", 3)
        set_setting("alert_dedup_seconds", 1)
        created = import_auth_log_file(str(log), mark_simulated=True)
        assert created >= 1
        sim = Alert.query.filter_by(is_simulated=True, attack_type="brute_force").count()
        real = Alert.query.filter_by(is_simulated=False, attack_type="brute_force").count()
        assert sim >= 1
        assert real == 0
