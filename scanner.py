import argparse
import ipaddress
import json
import re
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field

IOC_CONFIG_FILE = "iocs.json"


@dataclass
class ScanStats:
    """Running totals collected while a log file is scanned."""

    lines_scanned: int = 0
    total_findings: int = 0
    findings_by_type: Counter[str] = field(default_factory=Counter)


def load_patterns() -> dict[str, str]:
    with open(IOC_CONFIG_FILE, "r") as f:
        return json.load(f)


def is_valid_ipv4(value: str) -> bool:
    """Return whether a value is a valid IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def find_iocs(line: str, patterns: Mapping[str, str]) -> list[tuple[str, str]]:
    """Return every IOC found in a single line of log text."""
    findings = []

    for ioc_type, pattern in patterns.items():
        for match in re.findall(pattern, line):
            if ioc_type == "ipv4" and not is_valid_ipv4(match):
                continue
            findings.append((ioc_type, match))

    return findings


def scan_file(
    log_file: str,
    patterns: Mapping[str, str],
    stats: ScanStats | None = None,
) -> Iterator[tuple[int, str, str, str]]:
    """Yield the line number, IOC type, match, and source line for each finding."""
    if stats is None:
        stats = ScanStats()

    with open(log_file, "r") as f:
        for line_number, line in enumerate(f, start=1):
            stats.lines_scanned = line_number
            line = line.rstrip()
            for ioc_type, match in find_iocs(line, patterns):
                stats.total_findings += 1
                stats.findings_by_type[ioc_type] += 1
                yield line_number, ioc_type, match, line


def parse_args():
    parser = argparse.ArgumentParser(description="Scan a log file for IOCs.")
    parser.add_argument("log_file", help="Path to the log file to scan")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
        help="Output format (default: text)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    patterns = load_patterns()
    stats = ScanStats()
    json_findings = []

    for line_number, ioc_type, match, line in scan_file(
        args.log_file, patterns, stats
    ):
        if args.output_format == "text":
            print(f"[{ioc_type}] line {line_number}: {match} -> {line}")
        else:
            json_findings.append(
                {
                    "type": ioc_type,
                    "value": match,
                    "line_number": line_number,
                    "context": line,
                }
            )

    if args.output_format == "json":
        report = {
            "file": args.log_file,
            "summary": {
                "lines_scanned": stats.lines_scanned,
                "total_findings": stats.total_findings,
                "findings_by_type": dict(sorted(stats.findings_by_type.items())),
            },
            "findings": json_findings,
        }
        print(json.dumps(report, indent=2))
    else:
        print("\nScan summary")
        print(f"File: {args.log_file}")
        print(f"Lines scanned: {stats.lines_scanned}")
        print(f"Total findings: {stats.total_findings}")
        for ioc_type, count in sorted(stats.findings_by_type.items()):
            print(f"  {ioc_type}: {count}")


if __name__ == "__main__":
    main()
