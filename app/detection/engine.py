"""منسّق محرك الكشف."""
from __future__ import annotations

from app.detection import port_scan, dos_detection, brute_force, malware_indicators, suspicious_connections
from app.models.detection import DetectionRule


class DetectionEngine:
    """يمرّر أحداث الشبكة عبر وحدات الكشف المفعّلة."""

    def process_packet_meta(self, meta: dict) -> list:
        alerts = []
        rules = {r.rule_key: r for r in DetectionRule.query.all()}

        if self._enabled(rules, "port_scan"):
            a = port_scan.evaluate(meta, rules.get("port_scan"))
            if a:
                alerts.append(a)

        if self._enabled(rules, "dos_ddos"):
            a = dos_detection.evaluate(meta, rules.get("dos_ddos"))
            if a:
                alerts.append(a)

        if self._enabled(rules, "suspicious_connections"):
            a = suspicious_connections.evaluate(meta, rules.get("suspicious_connections"))
            if a:
                alerts.append(a)

        if self._enabled(rules, "malware_traffic"):
            a = malware_indicators.evaluate(meta, rules.get("malware_traffic"))
            if a:
                alerts.append(a)

        return alerts

    def process_auth_failure(self, event: dict) -> list:
        rules = {r.rule_key: r for r in DetectionRule.query.all()}
        if not self._enabled(rules, "brute_force"):
            return []
        a = brute_force.evaluate(event, rules.get("brute_force"))
        return [a] if a else []

    @staticmethod
    def _enabled(rules: dict, key: str) -> bool:
        r = rules.get(key)
        return bool(r and r.enabled and r.status != "disabled")
