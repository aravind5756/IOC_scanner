"""Core IOC detection functionality shared by all user interfaces."""

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
    """Load IOC patterns from the default JSON configuration file."""
    with open(IOC_CONFIG_FILE, "r") as f:
        return json.load(f)


def is_valid_ipv4(value: str) -> bool:
    """Return whether a value is a valid IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def classify_ipv4(value: str) -> str:
    """Describe the network scope of an IPv4 address."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"

    if not isinstance(address, ipaddress.IPv4Address):
        return "invalid"
    if address.is_unspecified:
        return "unspecified"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved:
        return "reserved"
    if address.is_private:
        return "private"
    if address.is_global:
        return "public"
    return "special-use"


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
