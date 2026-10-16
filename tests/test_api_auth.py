"""اختبارات API والصلاحيات وغياب Scapy."""
from app.integrations import scapy_sensor


def test_login_required_api(client):
    res = client.get("/api/stats")
    assert res.status_code in (302, 401)


def test_api_stats_authenticated(auth_client):
    res = auth_client.get("/api/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_alerts" in data
    assert "standby" in data
    assert data["total_alerts"] == 0 or isinstance(data["total_alerts"], int)


def test_viewer_cannot_start_capture(viewer_client):
    res = viewer_client.post("/sensors/start", follow_redirects=False)
    assert res.status_code == 403


def test_scapy_status_handles_absence(app):
    status = scapy_sensor.capture_manager.scapy_status()
    assert "available" in status
    assert "running" in status
    # سواء كان متاحاً أم لا يجب ألا يرمي استثناء
    assert isinstance(status["available"], bool)


def test_capture_stop_when_not_running(app):
    ok, msg = scapy_sensor.capture_manager.stop(app)
    assert ok is True
