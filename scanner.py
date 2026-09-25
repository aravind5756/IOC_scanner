import argparse
import json
import sys
from contextlib import nullcontext
from dataclasses import asdict
from pathlib import Path

from ioc_scanner import (
    ALLOWLIST_CONFIG_FILE,
    ConfigurationError,
    IOC_CONFIG_FILE,
    ScanStats,
    classify_ipv4,
    collect_scan_metadata,
    detect_repeated_failed_logins,
    detect_success_after_failed_logins,
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
    parser.add_argument(
        "--failed-login-window",
        type=positive_integer,
        default=5,
        metavar="MINUTES",
        help="Time window for failed login alerts (default: 5 minutes)",
    )
    parser.add_argument(
        "--patterns-file",
        default=IOC_CONFIG_FILE,
        help=f"IOC pattern configuration (default: {IOC_CONFIG_FILE})",
    )
    parser.add_argument(
        "--allowlist-file",
        default=ALLOWLIST_CONFIG_FILE,
        help=f"Trusted IOC configuration (default: {ALLOWLIST_CONFIG_FILE})",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.output:
        output_path = Path(args.output).resolve()
        protected_files = (
            (args.log_file, "log file"),
            (args.patterns_file, "IOC pattern configuration"),
            (args.allowlist_file, "allowlist configuration"),
        )
        for protected_file, description in protected_files:
            if Path(protected_file).resolve() == output_path:
                raise SystemExit(
                    f"Error: the output file must differ from the {description}."
                )

    try:
        patterns = load_patterns(args.patterns_file)
        allowlist = load_allowlist(args.allowlist_file)
    except ConfigurationError as error:
        raise SystemExit(f"Configuration error: {error}") from error
    metadata = collect_scan_metadata(args.log_file)
    with open(args.log_file, "r") as log_file:
        log_lines = log_file.readlines()

    detection_settings = {
        "threshold": args.failed_login_threshold,
        "window_minutes": args.failed_login_window,
    }
    alerts = detect_repeated_failed_logins(log_lines, **detection_settings)
    alerts.extend(
        detect_success_after_failed_logins(log_lines, **detection_settings)
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
                "metadata": asdict(metadata),
                "configuration": {
                    "patterns_file": args.patterns_file,
                    "allowlist_file": args.allowlist_file,
                },
                "summary": {
                    "lines_scanned": stats.lines_scanned,
                    "total_findings": stats.total_findings,
                    "allowlisted_findings": stats.allowlisted_findings,
                    "total_alerts": len(alerts),
                    "failed_login_threshold": args.failed_login_threshold,
                    "failed_login_window_minutes": args.failed_login_window,
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
            print(f"File size: {metadata.size_bytes} bytes", file=output_stream)
            print(f"SHA-256: {metadata.sha256}", file=output_stream)
            print(f"Scanned at: {metadata.scanned_at_utc}", file=output_stream)
            print(f"IOC patterns: {args.patterns_file}", file=output_stream)
            print(f"Allowlist: {args.allowlist_file}", file=output_stream)
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
            print(
                f"Failed-login rule: {args.failed_login_threshold} attempts "
                f"within {args.failed_login_window} minutes",
                file=output_stream,
            )
            for alert in alerts:
                print(
                    f"[{alert.severity.upper()}] {alert.rule_id}: {alert.title}",
                    file=output_stream,
                )
                print(f"  Source IP: {alert.source_ip}", file=output_stream)
                print(f"  Occurrences: {alert.occurrences}", file=output_stream)
                evidence = ", ".join(str(line) for line in alert.evidence_lines)
                print(f"  Evidence lines: {evidence}", file=output_stream)
                if alert.window_minutes is not None:
                    print(
                        f"  Detection window: {alert.window_minutes} minutes",
                        file=output_stream,
                    )

    if args.output:
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
