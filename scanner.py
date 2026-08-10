import json
import re

LOG_FILE = "sample.log"
IOC_CONFIG_FILE = "iocs.json"


def load_patterns():
    with open(IOC_CONFIG_FILE, "r") as f:
        return json.load(f)


def main():
    patterns = load_patterns()

    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.rstrip()
            for ioc_type, pattern in patterns.items():
                matches = re.findall(pattern, line)
                for match in matches:
                    print(f"[{ioc_type}] {match} -> {line}")


if __name__ == "__main__":
    main()
