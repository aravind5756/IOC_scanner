"""Reusable IOC scanning package."""

from .detections import SecurityAlert, detect_repeated_failed_logins
from .engine import (
    ScanStats,
    classify_ipv4,
    find_iocs,
    is_allowlisted,
    load_allowlist,
    load_patterns,
    scan_file,
)

__all__ = [
    "ScanStats",
    "SecurityAlert",
    "classify_ipv4",
    "detect_repeated_failed_logins",
    "find_iocs",
    "is_allowlisted",
    "load_allowlist",
    "load_patterns",
    "scan_file",
]
