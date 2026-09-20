import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import scanner

IPV4_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
MD5_PATTERN = r"\b[a-fA-F0-9]{32}\b"
MD5_VALUE = "d41d8cd98f00b204e9800998ecf8427e"
PATTERNS = {"ipv4": IPV4_PATTERN, "md5_hash": MD5_PATTERN}


class CLIReportTests(unittest.TestCase):
    def run_scanner(
        self,
        output_format,
        log_content=None,
        threshold=None,
        window_minutes=None,
        allowlist=None,
    ):
        if log_content is None:
            log_content = f"Connection from 10.0.0.5\nHash {MD5_VALUE}\n"
        if allowlist is None:
            allowlist = {}

        with tempfile.TemporaryDirectory() as temporary_directory:
            log_file = Path(temporary_directory) / "events.log"
            log_file.write_text(log_content, encoding="utf-8")
            arguments = ["scanner.py", str(log_file)]
            if output_format == "json":
                arguments.extend(["--format", "json"])
            if threshold is not None:
                arguments.extend(["--failed-login-threshold", str(threshold)])
            if window_minutes is not None:
                arguments.extend(["--failed-login-window", str(window_minutes)])

            output = io.StringIO()
            with (
                patch.object(sys, "argv", arguments),
                patch("scanner.load_patterns", return_value=PATTERNS),
                patch("scanner.load_allowlist", return_value=allowlist),
                redirect_stdout(output),
            ):
                scanner.main()

        return output.getvalue()

    def test_text_report_displays_scope_for_ipv4_only(self):
        output = self.run_scanner("text")

        self.assertIn("10.0.0.5 (private)", output)
        self.assertIn(f"[md5_hash] line 2: {MD5_VALUE} ->", output)

    def test_json_report_includes_scope_for_ipv4_only(self):
        report = json.loads(self.run_scanner("json"))

        ipv4_finding, hash_finding = report["findings"]
        self.assertEqual(ipv4_finding["network_scope"], "private")
        self.assertNotIn("network_scope", hash_finding)

    def test_text_report_displays_failed_login_alert(self):
        log_content = (
            "Failed login from 185.220.101.7\n"
            "Failed password from 185.220.101.7\n"
            "FAILED LOGIN from 185.220.101.7\n"
        )

        output = self.run_scanner("text", log_content, threshold=3)

        self.assertIn("Security alerts: 1", output)
        self.assertIn("[HIGH] AUTH-001: Repeated failed login attempts", output)
        self.assertIn("Source IP: 185.220.101.7", output)
        self.assertIn("Evidence lines: 1, 2, 3", output)

    def test_time_window_keeps_spread_out_attempts_below_alert_threshold(self):
        log_content = (
            "2026-08-10 09:00:00 Failed login from 185.220.101.7\n"
            "2026-08-10 09:10:00 Failed login from 185.220.101.7\n"
        )

        output = self.run_scanner(
            "text", log_content, threshold=2, window_minutes=5
        )

        self.assertIn("Security alerts: 0", output)
        self.assertIn("Failed-login rule: 2 attempts within 5 minutes", output)

    def test_json_report_includes_failed_login_alert(self):
        log_content = (
            "Failed login from 185.220.101.7\n"
            "Failed login from 185.220.101.7\n"
        )

        report = json.loads(self.run_scanner("json", log_content, threshold=2))

        self.assertEqual(report["summary"]["total_alerts"], 1)
        self.assertEqual(
            report["alerts"][0],
            {
                "rule_id": "AUTH-001",
                "title": "Repeated failed login attempts",
                "severity": "high",
                "source_ip": "185.220.101.7",
                "occurrences": 2,
                "evidence_lines": [1, 2],
                "window_minutes": None,
            },
        )

    def test_text_report_excludes_allowlisted_findings(self):
        output = self.run_scanner(
            "text", allowlist={"ipv4": ["10.0.0.5"]}
        )

        self.assertNotIn("10.0.0.5", output)
        self.assertIn(MD5_VALUE, output)
        self.assertIn("Total findings: 1", output)
        self.assertIn("Allowlisted findings: 1", output)
        self.assertIn("  ipv4: 1", output)

    def test_json_report_excludes_allowlisted_findings(self):
        report = json.loads(
            self.run_scanner("json", allowlist={"ipv4": ["10.0.0.5"]})
        )

        self.assertEqual(report["summary"]["total_findings"], 1)
        self.assertEqual(report["summary"]["findings_by_type"], {"md5_hash": 1})
        self.assertEqual(report["summary"]["allowlisted_findings"], 1)
        self.assertEqual(report["summary"]["allowlisted_by_type"], {"ipv4": 1})
        self.assertEqual(report["findings"][0]["value"], MD5_VALUE)


if __name__ == "__main__":
    unittest.main()
