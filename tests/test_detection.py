"""اختبارات محرك الكشف."""
from datetime import datetime, timezone

from app.detection import port_scan, dos_detection, brute_force
from app.detection.port_scan import reset_state as reset_ps
from app.detection.dos_detection import reset_state as reset_dos
from app.detection.brute_force import reset_state as reset_bf
from app.models.alert import Alert
from app.services.settings_service import set_setting


def test_port_scan_threshold(app):
    reset_ps()
    with app.app_context():
        set_setting("port_scan_threshold", 5)
        set_setting("port_scan_window_seconds", 60)
        set_setting("alert_dedup_seconds", 1)
        now = datetime.now(timezone.utc)
        created = None
        for port in range(1, 8):
            alert = port_scan.evaluate(
                {
                    "src_ip": "10.0.0.50",
                    "dst_ip": "10.0.0.1",
                    "dst_port": port,
                    "protocol": "TCP",
                    "flags": "S",
                    "observed_at": now,
                    "is_simulated": False,
                    "source_type": "detection_engine",
                }
            )
            if alert is not None:
                created = alert
        assert created is not None
        assert created.attack_type == "port_scan"
        assert created.is_simulated is False
        assert "مؤشر" in created.title or "فحص" in created.title


def test_port_scan_dedup(app):
    reset_ps()
    with app.app_context():
        set_setting("port_scan_threshold", 3)
        set_setting("alert_dedup_seconds", 300)
        now = datetime.now(timezone.utc)
        first = None
        second = None
        for port in range(1, 6):
            alert = port_scan.evaluate(
                {
                    "src_ip": "10.0.0.77",
                    "dst_ip": "10.0.0.1",
                    "dst_port": port,
                    "protocol": "TCP",
                    "observed_at": now,
                    "is_simulated": False,
                }
            )
            if alert and first is None:
                first = alert
            elif alert:
                second = alert
        assert first is not None
        assert second is None
        assert Alert.query.filter_by(src_ip="10.0.0.77", is_simulated=False).count() == 1


def test_dos_syn_threshold(app):
    reset_dos()
    with app.app_context():
        set_setting("dos_pps_threshold", 1000)
        set_setting("dos_syn_threshold", 5)
        set_setting("dos_window_seconds", 10)
        set_setting("alert_dedup_seconds", 1)
        now = datetime.now(timezone.utc)
        alert = None
        for i in range(8):
            result = dos_detection.evaluate(
                {
                    "src_ip": f"10.1.1.{i % 3}",
                    "dst_ip": "10.0.0.9",
                    "protocol": "TCP",
                    "flags": "S",
                    "observed_at": now,
                    "is_simulated": False,
                }
            )
            if result is not None:
                alert = result
        assert alert is not None
        assert alert.attack_type in ("dos", "ddos")
        assert "مؤشر" in (alert.description or "") or "مؤشر" in alert.title


def test_brute_force_from_auth_only(app):
    reset_bf()
    with app.app_context():
        set_setting("brute_force_threshold", 3)
        set_setting("brute_force_window_seconds", 300)
        set_setting("alert_dedup_seconds", 1)
        now = datetime.now(timezone.utc)
        alert = None
        for _ in range(4):
            result = brute_force.evaluate(
                {
                    "src_ip": "203.0.113.10",
                    "username": "root",
                    "success": False,
                    "auth_result": "failure",
                    "service": "ssh",
                    "observed_at": now,
                    "is_simulated": False,
                }
            )
            if result is not None:
                alert = result
        assert alert is not None
        assert alert.attack_type == "brute_force"
        assert alert.source_type == "auth_log"


def test_simulated_not_in_real_stats(app):
    reset_ps()
    with app.app_context():
        from app.services import stats as stats_service
        from app.services.alert_service import create_alert

        set_setting("alert_dedup_seconds", 1)
        create_alert(
            attack_type="port_scan",
            title="تنبيه تجريبي",
            detection_rule="test",
            is_simulated=True,
            source_type="simulated",
            src_ip="1.2.3.4",
        )
        create_alert(
            attack_type="port_scan",
            title="تنبيه حقيقي",
            detection_rule="test",
            is_simulated=False,
            source_type="detection_engine",
            src_ip="5.6.7.8",
        )
        s = stats_service.dashboard_stats()
        assert s["total_alerts"] == 1
        assert Alert.query.filter_by(is_simulated=True).count() >= 1
