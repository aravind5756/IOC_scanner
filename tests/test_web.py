import io
import unittest
from unittest.mock import patch

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

    def test_health_endpoint_reports_ok(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})

    @patch("ioc_scanner.web.load_allowlist", return_value={})
    @patch("ioc_scanner.web.load_patterns", return_value={"ipv4": IPV4_PATTERN})
    def test_scan_upload_returns_findings_and_network_scope(
        self, mock_load_patterns, mock_load_allowlist
    ):
        response = self.client.post(
            "/scan",
            data={
                "log_file": (
                    io.BytesIO(b"Connection from 10.0.0.5\nNo indicator here\n"),
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
        self.assertEqual(
            report["alerts"][0],
            {
                "rule_id": "AUTH-001",
                "title": "Repeated failed login attempts",
                "severity": "high",
                "source_ip": "185.220.101.7",
                "occurrences": 5,
                "evidence_lines": [1, 2, 3, 4, 5],
            },
        )
        mock_load_patterns.assert_called_once_with()
        mock_load_allowlist.assert_called_once_with()

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


if __name__ == "__main__":
    unittest.main()
