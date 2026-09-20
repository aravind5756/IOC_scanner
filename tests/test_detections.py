import unittest

from ioc_scanner.detections import detect_repeated_failed_logins


class RepeatedFailedLoginTests(unittest.TestCase):
    def test_creates_alert_when_threshold_is_reached(self):
        lines = [
            "Failed login from 185.220.101.7",
            "Failed password for root from 185.220.101.7",
            "FAILED LOGIN from 185.220.101.7",
        ]

        alerts = detect_repeated_failed_logins(lines, threshold=3)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "AUTH-001")
        self.assertEqual(alert.title, "Repeated failed login attempts")
        self.assertEqual(alert.severity, "high")
        self.assertEqual(alert.source_ip, "185.220.101.7")
        self.assertEqual(alert.occurrences, 3)
        self.assertEqual(alert.evidence_lines, (1, 2, 3))
        self.assertIsNone(alert.window_minutes)

    def test_alerts_for_attempts_inside_the_time_window(self):
        lines = [
            "2026-08-10 09:00:00 Failed login from 185.220.101.7",
            "2026-08-10 09:02:00 Failed login from 185.220.101.7",
            "2026-08-10 09:04:00 Failed login from 185.220.101.7",
        ]

        alerts = detect_repeated_failed_logins(
            lines, threshold=3, window_minutes=5
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].occurrences, 3)
        self.assertEqual(alerts[0].evidence_lines, (1, 2, 3))
        self.assertEqual(alerts[0].window_minutes, 5)

    def test_does_not_combine_attempts_spread_outside_the_time_window(self):
        lines = [
            "2026-08-10 09:00:00 Failed login from 185.220.101.7",
            "2026-08-10 09:10:00 Failed login from 185.220.101.7",
            "2026-08-10 09:20:00 Failed login from 185.220.101.7",
        ]

        alerts = detect_repeated_failed_logins(
            lines, threshold=3, window_minutes=5
        )

        self.assertEqual(alerts, [])

    def test_does_not_alert_below_threshold(self):
        lines = [
            "Failed login from 185.220.101.7",
            "Successful login from 185.220.101.7",
            "Failed login from 185.220.101.7",
        ]

        alerts = detect_repeated_failed_logins(lines, threshold=3)

        self.assertEqual(alerts, [])

    def test_ignores_invalid_ip_candidates(self):
        lines = ["Failed login from 999.999.999.999"]

        alerts = detect_repeated_failed_logins(lines, threshold=1)

        self.assertEqual(alerts, [])

    def test_counts_an_ip_once_per_log_line(self):
        lines = [
            "Failed login from 8.8.8.8 reported by 8.8.8.8",
            "Failed login from 8.8.8.8 reported by 8.8.8.8",
        ]

        alerts = detect_repeated_failed_logins(lines, threshold=2)

        self.assertEqual(alerts[0].occurrences, 2)
        self.assertEqual(alerts[0].evidence_lines, (1, 2))

    def test_rejects_thresholds_below_one(self):
        with self.assertRaisesRegex(ValueError, "threshold must be at least 1"):
            detect_repeated_failed_logins([], threshold=0)

    def test_rejects_time_windows_below_one_minute(self):
        with self.assertRaisesRegex(ValueError, "window must be at least 1 minute"):
            detect_repeated_failed_logins([], window_minutes=0)


if __name__ == "__main__":
    unittest.main()
