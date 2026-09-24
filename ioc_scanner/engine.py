"""Core IOC detection functionality shared by all user interfaces."""

import ipaddress
import json
import re
from collections import Counter
from collections.abc import Collection, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

IOC_CONFIG_FILE = "iocs.json"
ALLOWLIST_CONFIG_FILE = "allowlist.json"


class ConfigurationError(ValueError):
    """Raised when a scanner configuration file cannot be used safely."""


@dataclass
class ScanStats:
    """Running totals collected while a log file is scanned."""

    lines_scanned: int = 0
    total_findings: int = 0
    findings_by_type: Counter[str] = field(default_factory=Counter)
    allowlisted_findings: int = 0
    allowlisted_by_type: Counter[str] = field(default_factory=Counter)


def load_config_object(config_file: str | Path, label: str) -> dict:
    """Load a JSON configuration file and require an object at its root."""
    try:
        with open(config_file, "r", encoding="utf-8") as file_stream:
            config = json.load(file_stream)
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigurationError(
            f"Could not load {label} configuration '{config_file}': {error}"
        ) from error

    if not isinstance(config, dict):
        raise ConfigurationError(f"The {label} configuration must be a JSON object.")
    return config


def load_patterns(config_file: str | Path = IOC_CONFIG_FILE) -> dict[str, str]:
    """Load and validate IOC regular expressions."""
    patterns = load_config_object(config_file, "IOC pattern")
    if not patterns:
        raise ConfigurationError("The IOC pattern configuration cannot be empty.")

    for ioc_type, pattern in patterns.items():
        if not isinstance(ioc_type, str) or not ioc_type or not isinstance(pattern, str):
            raise ConfigurationError(
                "Each IOC pattern must have a non-empty name and string value."
            )
        try:
            re.compile(pattern)
        except re.error as error:
            raise ConfigurationError(
                f"IOC pattern '{ioc_type}' is not a valid regular expression: {error}"
            ) from error
    return patterns


def load_allowlist(
    config_file: str | Path = ALLOWLIST_CONFIG_FILE,
) -> dict[str, list[str]]:
    """Load and validate trusted IOC values."""
    allowlist = load_config_object(config_file, "allowlist")
    for ioc_type, values in allowlist.items():
        valid_values = isinstance(values, list) and all(
            isinstance(value, str) and value for value in values
        )
        if not isinstance(ioc_type, str) or not ioc_type or not valid_values:
            raise ConfigurationError(
                "Each allowlist entry must have a non-empty name and a list of values."
            )
    return allowlist


def is_allowlisted(
    ioc_type: str,
    value: str,
    allowlist: Mapping[str, Collection[str]],
) -> bool:
    """Return whether an IOC exactly matches a trusted value."""
    return value in allowlist.get(ioc_type, ())


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


def find_iocs(
    line: str,
    patterns: Mapping[str, str],
    allowlist: Mapping[str, Collection[str]] | None = None,
) -> list[tuple[str, str]]:
    """Return every IOC found in a single line of log text."""
    findings = []
    allowlist = allowlist or {}

    for ioc_type, pattern in patterns.items():
        for match in re.findall(pattern, line):
            if ioc_type == "ipv4" and not is_valid_ipv4(match):
                continue
            if is_allowlisted(ioc_type, match, allowlist):
                continue
            findings.append((ioc_type, match))

    return findings


def scan_file(
    log_file: str,
    patterns: Mapping[str, str],
    stats: ScanStats | None = None,
    allowlist: Mapping[str, Collection[str]] | None = None,
) -> Iterator[tuple[int, str, str, str]]:
    """Yield the line number, IOC type, match, and source line for each finding."""
    if stats is None:
        stats = ScanStats()
    allowlist = allowlist or {}

    with open(log_file, "r") as f:
        for line_number, line in enumerate(f, start=1):
            stats.lines_scanned = line_number
            line = line.rstrip()
            for ioc_type, match in find_iocs(line, patterns):
                if is_allowlisted(ioc_type, match, allowlist):
                    stats.allowlisted_findings += 1
                    stats.allowlisted_by_type[ioc_type] += 1
                    continue
                stats.total_findings += 1
                stats.findings_by_type[ioc_type] += 1
                yield line_number, ioc_type, match, line
