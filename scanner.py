import argparse
import json
import re
from collections.abc import Iterator, Mapping

IOC_CONFIG_FILE = "iocs.json"


def load_patterns() -> dict[str, str]:
    with open(IOC_CONFIG_FILE, "r") as f:
        return json.load(f)


def find_iocs(line: str, patterns: Mapping[str, str]) -> list[tuple[str, str]]:
    """Return every IOC found in a single line of log text."""
    findings = []

    for ioc_type, pattern in patterns.items():
        for match in re.findall(pattern, line):
            findings.append((ioc_type, match))

    return findings


def scan_file(
    log_file: str, patterns: Mapping[str, str]
) -> Iterator[tuple[int, str, str, str]]:
    """Yield the line number, IOC type, match, and source line for each finding."""
    with open(log_file, "r") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.rstrip()
            for ioc_type, match in find_iocs(line, patterns):
                yield line_number, ioc_type, match, line


def parse_args():
    parser = argparse.ArgumentParser(description="Scan a log file for IOCs.")
    parser.add_argument("log_file", help="Path to the log file to scan")
    return parser.parse_args()


def main():
    args = parse_args()
    patterns = load_patterns()

    for _, ioc_type, match, line in scan_file(args.log_file, patterns):
        print(f"[{ioc_type}] {match} -> {line}")


if __name__ == "__main__":
    main()
