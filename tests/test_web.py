import hashlib
import io
import unittest
from unittest.mock import patch

from ioc_scanner.engine import ConfigurationError
from ioc_scanner.web import create_app

IPV4_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"


class WebApplicationTests(unittest.TestCase):
    def setUp(self):
        app = create_app()
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_home_page_loads(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"IOC Scanner", response.data)
        self.assertIn(b"Allowlisted", response.data)
        self.assertIn(b"Evidence details", response.data)
        self.assertIn(b"Download JSON report", response.data)
        self.assertIn(b'id="download-report"', response.data)
        self.assertIn(b'id="allowlisted-findings"', response.data)
        self.assertIn(b'name="failed_login_threshold"', response.data)
        self.assertIn(b'name="failed_login_window"', response.data)

    def test_health_endpoint_reports_ok(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})

    @patch("ioc_scanner.web.load_allowlist", return_value={})
    @patch("ioc_scanner.web.load_patterns", return_value={"ipv4": IPV4_PATTERN})
    def test_scan_upload_returns_findings_and_network_scope(
        self, mock_load_patterns, mock_load_allowlist
    ):
        log_content = b"Connection from 10.0.0.5\nNo indicator here\n"
        response = self.client.post(
            "/scan",
            data={
                "log_file": (
                    io.BytesIO(log_content),
                    "events.log",
                )
            },
            content_type="multipart/form-data",
        )

        report = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(report["file"], "events.log")
        self.assertEqual(report["summary"]["lines_scanned"], 2)
        self.assertEqual(report["summary"]["total_findings"], 1)
        self.assertEqual(report["summary"]["total_alerts"], 0)
        self.assertEqual(report["metadata"]["file_name"], "events.log")
        self.assertEqual(report["metadata"]["size_bytes"], len(log_content))
        self.assertEqual(
            report["metadata"]["sha256"], hashlib.sha256(log_content).hexdigest()
        )
        self.assertTrue(report["metadata"]["scanned_at_utc"].endswith("Z"))
        self.assertEqual(report["findings"][0]["value"], "10.0.0.5")
        self.assertEqual(report["findings"][0]["network_scope"], "private")
        mock_load_patterns.assert_called_once_with()
        mock_load_allowlist.assert_called_once_with()

    @patch("ioc_scanner.web.load_allowlist", return_value={})
    @patch("ioc_scanner.web.load_patterns", return_value={"ipv4": IPV4_PATTERN})
    def test_scan_upload_returns_failed_login_alert(
        self, mock_load_patterns, mock_load_allowlist
    ):
        failed_logins = b"\n".join(
            [b"Failed login from 185.220.101.7"] * 5
        )
        response = self.client.post(
            "/scan",
            data={"log_file": (io.BytesIO(failed_logins), "auth.log")},
            content_type="multipart/form-data",
        )

        report = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(report["summary"]["total_alerts"], 1)
        self.assertEqual(report["summary"]["failed_login_threshold"], 5)
        self.assertEqual(report["summary"]["failed_login_window_minutes"], 5)
        self.assertEqual(
            report["alerts"][0],
            {
                "rule_id": "AUTH-001",
                "title": "Repeated failed login attempts",
                "severity": "high",
                "source_ip": "185.220.101.7",
                "occurrences": 5,
                "evidence_lines": [1, 2, 3, 4, 5],
                "window_minutes": None,
            },
        )
        mock_load_patterns.assert_called_once_with()
        mock_load_allowlist.assert_called_once_with()

    @patch("ioc_scanner.web.load_allowlist", return_value={})
    @patch("ioc_scanner.web.load_patterns", return_value={})
    def test_scan_upload_uses_custom_failed_login_threshold(
        self, mock_load_patterns, mock_load_allowlist
    ):
        failed_logins = b"\n".join(
            [
                b"2026-08-10 09:00:00 Failed login from 185.220.101.7",
                b"2026-08-10 09:01:00 Failed login from 185.220.101.7",
                b"2026-08-10 09:02:00 Failed login from 185.220.101.7",
            ]
        )
        response = self.client.post(
            "/scan",
            data={
                "log_file": (io.BytesIO(failed_logins), "auth.log"),
                "failed_login_threshold": "3",
                "failed_login_window": "3",
            },
            content_type="multipart/form-data",
        )

        report = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(report["summary"]["failed_login_threshold"], 3)
        self.assertEqual(report["summary"]["failed_login_window_minutes"], 3)
        self.assertEqual(report["summary"]["total_alerts"], 1)
        self.assertEqual(report["alerts"][0]["window_minutes"], 3)
        mock_load_patterns.assert_called_once_with()
        mock_load_allowlist.assert_called_once_with()

    @patch("ioc_scanner.web.load_allowlist", return_value={})
    @patch("ioc_scanner.web.load_patterns", return_value={})
    def test_scan_upload_returns_success_after_failures_alert(
        self, mock_load_patterns, mock_load_allowlist
    ):
        authentication_events = b"\n".join(
            [
                b"2026-08-10 09:00:00 Failed login from 185.220.101.7",
                b"2026-08-10 09:01:00 Failed login from 185.220.101.7",
                b"2026-08-10 09:02:00 Accepted password from 185.220.101.7",
            ]
        )
        response = self.client.post(
            "/scan",
            data={
                "log_file": (io.BytesIO(authentication_events), "auth.log"),
                "failed_login_threshold": "2",
                "failed_login_window": "5",
            },
            content_type="multipart/form-data",
        )

        report = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(report["summary"]["total_alerts"], 2)
        self.assertEqual(
            [alert["rule_id"] for alert in report["alerts"]],
            ["AUTH-001", "AUTH-002"],
        )
        correlated_alert = report["alerts"][1]
        self.assertEqual(correlated_alert["severity"], "critical")
        self.assertEqual(correlated_alert["source_ip"], "185.220.101.7")
        self.assertEqual(correlated_alert["evidence_lines"], [1, 2, 3])
        self.assertEqual(correlated_alert["window_minutes"], 5)
        mock_load_patterns.assert_called_once_with()
        mock_load_allowlist.assert_called_once_with()

    def test_scan_upload_rejects_invalid_failed_login_threshold(self):
        response = self.client.post(
            "/scan",
            data={
                "log_file": (io.BytesIO(b"example"), "auth.log"),
                "failed_login_threshold": "0",
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(),
            {
                "error": (
                    "The failed-login threshold must be a whole number of at least 1."
                )
            },
        )

    def test_scan_upload_rejects_invalid_failed_login_window(self):
        response = self.client.post(
            "/scan",
            data={
                "log_file": (io.BytesIO(b"example"), "auth.log"),
                "failed_login_window": "0",
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(),
            {
                "error": (
                    "The failed-login window must be a whole number of at least "
                    "1 minute."
                )
            },
        )

    @patch(
        "ioc_scanner.web.load_allowlist",
        return_value={"ipv4": ["10.0.0.5"]},
    )
    @patch("ioc_scanner.web.load_patterns", return_value={"ipv4": IPV4_PATTERN})
    def test_scan_upload_excludes_allowlisted_findings(
        self, mock_load_patterns, mock_load_allowlist
    ):
        response = self.client.post(
            "/scan",
            data={
                "log_file": (
                    io.BytesIO(b"Trusted 10.0.0.5\nExternal 8.8.8.8\n"),
                    "events.log",
                )
            },
            content_type="multipart/form-data",
        )

        report = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(report["summary"]["total_findings"], 1)
        self.assertEqual(report["summary"]["findings_by_type"], {"ipv4": 1})
        self.assertEqual(report["summary"]["allowlisted_findings"], 1)
        self.assertEqual(report["summary"]["allowlisted_by_type"], {"ipv4": 1})
        self.assertEqual(report["findings"][0]["value"], "8.8.8.8")
        mock_load_patterns.assert_called_once_with()
        mock_load_allowlist.assert_called_once_with()

    def test_scan_upload_requires_a_file(self):
        response = self.client.post("/scan")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"error": "No log file was provided."})

    def test_scan_upload_rejects_unsupported_file_types(self):
        response = self.client.post(
            "/scan",
            data={"log_file": (io.BytesIO(b"example"), "events.csv")},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(),
            {"error": "Only .log and .txt files are supported."},
        )

    @patch(
        "ioc_scanner.web.load_patterns",
        side_effect=ConfigurationError("invalid IOC pattern"),
    )
    def test_scan_upload_reports_configuration_errors(self, mock_load_patterns):
        response = self.client.post(
            "/scan",
            data={"log_file": (io.BytesIO(b"example"), "events.log")},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.get_json(),
            {"error": "Scanner configuration error: invalid IOC pattern"},
        )
        mock_load_patterns.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
