import argparse
import json
import sys
from contextlib import nullcontext
from dataclasses import asdict
from pathlib import Path

from ioc_scanner import (
    ScanStats,
    classify_ipv4,
    detect_repeated_failed_logins,
    load_allowlist,
    load_patterns,
    scan_file,
)


def positive_integer(value: str) -> int:
    """Parse a command-line value that must be a positive integer."""
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a whole number") from error

    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


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
    parser.add_argument(
        "-o",
        "--output",
        help="Write the report to a file instead of standard output",
    )
    parser.add_argument(
        "--failed-login-threshold",
        type=positive_integer,
        default=5,
        help="Failed login attempts required for an alert (default: 5)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.output and Path(args.log_file).resolve() == Path(args.output).resolve():
        raise SystemExit("Error: the output file must be different from the log file.")

    patterns = load_patterns()
    allowlist = load_allowlist()
    with open(args.log_file, "r") as log_file:
        alerts = detect_repeated_failed_logins(
            log_file, threshold=args.failed_login_threshold
        )

    stats = ScanStats()
    json_findings = []

    output_context = (
        open(args.output, "w", encoding="utf-8")
        if args.output
        else nullcontext(sys.stdout)
    )

    with output_context as output_stream:
        for line_number, ioc_type, match, line in scan_file(
            args.log_file, patterns, stats, allowlist
        ):
            network_scope = classify_ipv4(match) if ioc_type == "ipv4" else None

            if args.output_format == "text":
                scope_label = f" ({network_scope})" if network_scope else ""
                print(
                    f"[{ioc_type}] line {line_number}: {match}{scope_label} -> {line}",
                    file=output_stream,
                )
            else:
                finding = {
                    "type": ioc_type,
                    "value": match,
                    "line_number": line_number,
                    "context": line,
                }
                if network_scope:
                    finding["network_scope"] = network_scope
                json_findings.append(finding)

        if args.output_format == "json":
            report = {
                "file": args.log_file,
                "summary": {
                    "lines_scanned": stats.lines_scanned,
                    "total_findings": stats.total_findings,
                    "allowlisted_findings": stats.allowlisted_findings,
                    "total_alerts": len(alerts),
                    "findings_by_type": dict(
                        sorted(stats.findings_by_type.items())
                    ),
                    "allowlisted_by_type": dict(
                        sorted(stats.allowlisted_by_type.items())
                    ),
                },
                "findings": json_findings,
                "alerts": [asdict(alert) for alert in alerts],
            }
            print(json.dumps(report, indent=2), file=output_stream)
        else:
            print("\nScan summary", file=output_stream)
            print(f"File: {args.log_file}", file=output_stream)
            print(f"Lines scanned: {stats.lines_scanned}", file=output_stream)
            print(f"Total findings: {stats.total_findings}", file=output_stream)
            for ioc_type, count in sorted(stats.findings_by_type.items()):
                print(f"  {ioc_type}: {count}", file=output_stream)

            print(
                f"\nAllowlisted findings: {stats.allowlisted_findings}",
                file=output_stream,
            )
            for ioc_type, count in sorted(stats.allowlisted_by_type.items()):
                print(f"  {ioc_type}: {count}", file=output_stream)

            print(f"\nSecurity alerts: {len(alerts)}", file=output_stream)
            for alert in alerts:
                print(
                    f"[{alert.severity.upper()}] {alert.rule_id}: {alert.title}",
                    file=output_stream,
                )
                print(f"  Source IP: {alert.source_ip}", file=output_stream)
                print(f"  Occurrences: {alert.occurrences}", file=output_stream)
                evidence = ", ".join(str(line) for line in alert.evidence_lines)
                print(f"  Evidence lines: {evidence}", file=output_stream)

    if args.output:
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
