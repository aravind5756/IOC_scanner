import argparse
import json
import re

IOC_CONFIG_FILE = "iocs.json"


def load_patterns():
    with open(IOC_CONFIG_FILE, "r") as f:
        return json.load(f)


def parse_args():
    parser = argparse.ArgumentParser(description="Scan a log file for IOCs.")
    parser.add_argument("log_file", help="Path to the log file to scan")
    return parser.parse_args()


def main():
    args = parse_args()
    patterns = load_patterns()

    with open(args.log_file, "r") as f:
        for line in f:
            line = line.rstrip()
            for ioc_type, pattern in patterns.items():
                matches = re.findall(pattern, line)
                for match in matches:
                    print(f"[{ioc_type}] {match} -> {line}")


if __name__ == "__main__":
    main()
