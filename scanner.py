import argparse
import json
import sys
from contextlib import nullcontext
from pathlib import Path

from ioc_scanner import ScanStats, load_patterns, scan_file


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
    return parser.parse_args()


def main():
    args = parse_args()

    if args.output and Path(args.log_file).resolve() == Path(args.output).resolve():
        raise SystemExit("Error: the output file must be different from the log file.")

    patterns = load_patterns()
    stats = ScanStats()
    json_findings = []

    output_context = (
        open(args.output, "w", encoding="utf-8")
        if args.output
        else nullcontext(sys.stdout)
    )

    with output_context as output_stream:
        for line_number, ioc_type, match, line in scan_file(
            args.log_file, patterns, stats
        ):
            if args.output_format == "text":
                print(
                    f"[{ioc_type}] line {line_number}: {match} -> {line}",
                    file=output_stream,
                )
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
                    "findings_by_type": dict(
                        sorted(stats.findings_by_type.items())
                    ),
                },
                "findings": json_findings,
            }
            print(json.dumps(report, indent=2), file=output_stream)
        else:
            print("\nScan summary", file=output_stream)
            print(f"File: {args.log_file}", file=output_stream)
            print(f"Lines scanned: {stats.lines_scanned}", file=output_stream)
            print(f"Total findings: {stats.total_findings}", file=output_stream)
            for ioc_type, count in sorted(stats.findings_by_type.items()):
                print(f"  {ioc_type}: {count}", file=output_stream)

    if args.output:
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
