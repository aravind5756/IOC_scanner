import tempfile
import unittest
from pathlib import Path

from ioc_scanner.engine import (
    ScanStats,
    classify_ipv4,
    find_iocs,
    is_valid_ipv4,
    scan_file,
)

IPV4_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
MD5_PATTERN = r"\b[a-fA-F0-9]{32}\b"
MD5_VALUE = "d41d8cd98f00b204e9800998ecf8427e"


class IPv4ValidationTests(unittest.TestCase):
    def test_accepts_valid_ipv4_addresses(self):
        for address in ("0.0.0.0", "8.8.8.8", "255.255.255.255"):
            with self.subTest(address=address):
                self.assertTrue(is_valid_ipv4(address))

    def test_rejects_invalid_or_non_ipv4_addresses(self):
        for address in ("999.999.999.999", "192.168.1.256", "2001:db8::1", "text"):
            with self.subTest(address=address):
                self.assertFalse(is_valid_ipv4(address))


class IPv4ClassificationTests(unittest.TestCase):
    def test_classifies_ipv4_network_scopes(self):
        expected_classifications = {
            "8.8.8.8": "public",
            "10.0.0.5": "private",
            "127.0.0.1": "loopback",
            "169.254.10.20": "link-local",
            "224.0.0.1": "multicast",
            "240.0.0.1": "reserved",
            "0.0.0.0": "unspecified",
        }

        for address, expected in expected_classifications.items():
            with self.subTest(address=address):
                self.assertEqual(classify_ipv4(address), expected)

    def test_marks_invalid_or_non_ipv4_values_as_invalid(self):
        for value in ("999.999.999.999", "2001:db8::1", "text"):
            with self.subTest(value=value):
                self.assertEqual(classify_ipv4(value), "invalid")


class IOCMatchingTests(unittest.TestCase):
    def test_finds_multiple_ioc_types_in_one_line(self):
        patterns = {"ipv4": IPV4_PATTERN, "md5_hash": MD5_PATTERN}

        findings = find_iocs(f"source=8.8.8.8 hash={MD5_VALUE}", patterns)

        self.assertEqual(
            findings,
            [("ipv4", "8.8.8.8"), ("md5_hash", MD5_VALUE)],
        )

    def test_ignores_invalid_ipv4_candidates(self):
        findings = find_iocs("source=999.999.999.999", {"ipv4": IPV4_PATTERN})

        self.assertEqual(findings, [])


class FileScanningTests(unittest.TestCase):
    def test_scan_file_returns_context_and_updates_statistics(self):
        patterns = {"ipv4": IPV4_PATTERN, "md5_hash": MD5_PATTERN}
        log_content = (
            "No indicators here\n"
            "Connection from 8.8.8.8\n"
            f"Hash {MD5_VALUE} sent to 1.1.1.1\n"
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            log_file = Path(temporary_directory) / "test.log"
            log_file.write_text(log_content, encoding="utf-8")
            stats = ScanStats()

            findings = list(scan_file(str(log_file), patterns, stats))

        self.assertEqual(
            findings,
            [
                (2, "ipv4", "8.8.8.8", "Connection from 8.8.8.8"),
                (3, "ipv4", "1.1.1.1", f"Hash {MD5_VALUE} sent to 1.1.1.1"),
                (3, "md5_hash", MD5_VALUE, f"Hash {MD5_VALUE} sent to 1.1.1.1"),
            ],
        )
        self.assertEqual(stats.lines_scanned, 3)
        self.assertEqual(stats.total_findings, 3)
        self.assertEqual(stats.findings_by_type, {"ipv4": 2, "md5_hash": 1})


if __name__ == "__main__":
    unittest.main()
