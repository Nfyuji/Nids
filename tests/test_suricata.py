"""اختبار قراءة Suricata EVE."""
from pathlib import Path

from app.integrations.suricata_eve import SuricataEveReader
from app.models.alert import Alert


SAMPLE = """
{"timestamp":"2024-01-01T12:00:00.000000+0000","event_type":"stats"}
{"timestamp":"2024-01-01T12:00:01.000000+0000","event_type":"alert","src_ip":"198.51.100.1","dest_ip":"10.0.0.5","src_port":44321,"dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2000001,"rev":1,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}
{"timestamp":"2024-01-01T12:00:02.000000+0000","event_type":"alert","src_ip":"198.51.100.1","dest_ip":"10.0.0.5","src_port":44322,"dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2000001,"rev":1,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}
""".strip()


def test_suricata_eve_import(app, tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text(SAMPLE + "\n", encoding="utf-8")
    reader = SuricataEveReader()
    with app.app_context():
        count = reader.import_file(app, str(eve), from_start=True)
        # السطر الثاني يُنشئ تنبيهاً؛ الثالث يُدمَج بسبب dedup لنفس sid+src+dst خلال النافذة
        assert count >= 1
        alerts = Alert.query.filter_by(source_type="suricata", is_simulated=False).all()
        assert len(alerts) >= 1
        assert alerts[0].external_sid == "2000001"
        assert alerts[0].detection_rule.startswith("suricata:")


def test_suricata_missing_file(app):
    reader = SuricataEveReader()
    with app.app_context():
        from app.services.settings_service import set_setting

        set_setting("suricata_eve_path", str(Path("missing-eve-file.json")))
        ok, msg = reader.start(app)
        assert ok is False
        assert "غير موجود" in msg or "missing" in msg.lower() or "ملف" in msg
