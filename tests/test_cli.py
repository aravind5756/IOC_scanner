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
    def run_scanner(self, output_format):
        log_content = f"Connection from 10.0.0.5\nHash {MD5_VALUE}\n"

        with tempfile.TemporaryDirectory() as temporary_directory:
            log_file = Path(temporary_directory) / "events.log"
            log_file.write_text(log_content, encoding="utf-8")
            arguments = ["scanner.py", str(log_file)]
            if output_format == "json":
                arguments.extend(["--format", "json"])

            output = io.StringIO()
            with (
                patch.object(sys, "argv", arguments),
                patch("scanner.load_patterns", return_value=PATTERNS),
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


if __name__ == "__main__":
    unittest.main()
