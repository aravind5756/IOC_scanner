import hashlib
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from ioc_scanner.reporting import collect_scan_metadata, safe_file_name


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
