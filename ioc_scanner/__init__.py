"""Reusable IOC scanning package."""

from .detections import (
    SecurityAlert,
    detect_repeated_failed_logins,
    detect_success_after_failed_logins,
)
from .engine import (
    ALLOWLIST_CONFIG_FILE,
    ConfigurationError,
    IOC_CONFIG_FILE,
    ScanStats,
    classify_ipv4,
    find_iocs,
    is_allowlisted,
    load_allowlist,
    load_patterns,
    scan_file,
)
from .reporting import ScanMetadata, collect_scan_metadata

__all__ = [
    "ALLOWLIST_CONFIG_FILE",
    "ConfigurationError",
    "IOC_CONFIG_FILE",
    "ScanStats",
    "ScanMetadata",
    "SecurityAlert",
    "classify_ipv4",
    "collect_scan_metadata",
    "detect_repeated_failed_logins",
    "detect_success_after_failed_logins",
    "find_iocs",
    "is_allowlisted",
    "load_allowlist",
    "load_patterns",
    "scan_file",
]
