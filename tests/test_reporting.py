import hashlib
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from ioc_scanner.detections import SecurityAlert
from ioc_scanner.reporting import (
    collect_scan_metadata,
    safe_file_name,
    summarise_alerts,
)


def make_alert(severity):
    return SecurityAlert(
        rule_id="TEST-001",
        title="Test alert",
        severity=severity,
        source_ip=None,
        occurrences=1,
        evidence_lines=(1,),
        window_minutes=None,
    )


class AlertSummaryTests(unittest.TestCase):
    def test_reports_no_risk_when_there_are_no_alerts(self):
        summary = summarise_alerts([])

        self.assertEqual(summary.risk_level, "none")
        self.assertEqual(
            summary.alerts_by_severity,
            {"low": 0, "medium": 0, "high": 0, "critical": 0},
        )

    def test_counts_each_severity_and_uses_the_highest_risk(self):
        alerts = [
            make_alert("low"),
            make_alert("high"),
            make_alert("critical"),
            make_alert("high"),
        ]

        summary = summarise_alerts(alerts)

        self.assertEqual(summary.risk_level, "critical")
        self.assertEqual(
            summary.alerts_by_severity,
            {"low": 1, "medium": 0, "high": 2, "critical": 1},
        )

    def test_normalises_severity_names(self):
        summary = summarise_alerts([make_alert("HIGH")])

        self.assertEqual(summary.risk_level, "high")
        self.assertEqual(summary.alerts_by_severity["high"], 1)

    def test_rejects_unknown_severity_names(self):
        with self.assertRaisesRegex(ValueError, "Unsupported alert severity: urgent"):
            summarise_alerts([make_alert("urgent")])


class ScanMetadataTests(unittest.TestCase):
    def test_collects_file_identity_metadata(self):
        content = b"\xff\xfe\x00binary evidence"

        with tempfile.TemporaryDirectory() as temporary_directory:
            log_file = Path(temporary_directory) / "events.log"
            log_file.write_bytes(content)

            metadata = collect_scan_metadata(log_file)

        self.assertEqual(metadata.file_name, "events.log")
        self.assertEqual(metadata.size_bytes, len(content))
        self.assertEqual(metadata.sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(len(metadata.sha256), 64)
        self.assertTrue(metadata.scanned_at_utc.endswith("Z"))
        datetime.fromisoformat(metadata.scanned_at_utc.replace("Z", "+00:00"))

    def test_uses_a_safe_display_name(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            log_file = Path(temporary_directory) / "temporary.log"
            log_file.write_text("example", encoding="utf-8")

            metadata = collect_scan_metadata(
                log_file, display_name=r"C:\fakepath\auth.log"
            )

        self.assertEqual(metadata.file_name, "auth.log")


class SafeFileNameTests(unittest.TestCase):
    def test_removes_windows_and_posix_directories(self):
        names = (r"C:\logs\auth.log", "/var/log/auth.log")

        for name in names:
            with self.subTest(name=name):
                self.assertEqual(safe_file_name(name), "auth.log")


if __name__ == "__main__":
    unittest.main()
