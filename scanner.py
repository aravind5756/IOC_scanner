import re

LOG_FILE = "sample.log"

IOC_PATTERNS = {
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "md5_hash": r"\b[a-fA-F0-9]{32}\b",
    "sha256_hash": r"\b[a-fA-F0-9]{64}\b",
}


def main():
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.rstrip()
            for ioc_type, pattern in IOC_PATTERNS.items():
                matches = re.findall(pattern, line)
                for match in matches:
                    print(f"[{ioc_type}] {match} -> {line}")


if __name__ == "__main__":
    main()
