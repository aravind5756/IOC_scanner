"""Report metadata helpers for identifying scanned evidence files."""

import hashlib
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .detections import SecurityAlert

HASH_CHUNK_SIZE = 64 * 1024
SEVERITY_LEVELS = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class ScanMetadata:
    """Identifying information recorded for a scanned file."""

    file_name: str
    size_bytes: int
    sha256: str
    scanned_at_utc: str


@dataclass(frozen=True)
class AlertSummary:
    """Severity totals and overall risk level for a collection of alerts."""

    risk_level: str
    alerts_by_severity: dict[str, int]


def summarise_alerts(alerts: Iterable[SecurityAlert]) -> AlertSummary:
    """Summarise alerts using the highest severity as the overall risk level."""
    severity_counts = Counter(alert.severity.lower() for alert in alerts)
    unsupported = set(severity_counts).difference(SEVERITY_LEVELS)
    if unsupported:
        invalid_severity = sorted(unsupported)[0]
        raise ValueError(f"Unsupported alert severity: {invalid_severity}")

    alerts_by_severity = {
        severity: severity_counts.get(severity, 0)
        for severity in SEVERITY_LEVELS
    }
    risk_level = "none"
    for severity in SEVERITY_LEVELS:
        if alerts_by_severity[severity] > 0:
            risk_level = severity

    return AlertSummary(
        risk_level=risk_level,
        alerts_by_severity=alerts_by_severity,
    )


def safe_file_name(file_name: str) -> str:
    """Remove any directory components from a supplied display name."""
    return file_name.replace("\\", "/").rsplit("/", maxsplit=1)[-1]


def collect_scan_metadata(
    file_path: str | Path, display_name: str | None = None
) -> ScanMetadata:
    """Collect reproducible identity metadata for a file being scanned."""
    path = Path(file_path)
    digest = hashlib.sha256()

    with path.open("rb") as file_stream:
        for chunk in iter(lambda: file_stream.read(HASH_CHUNK_SIZE), b""):
            digest.update(chunk)

    file_name = safe_file_name(display_name) if display_name else path.name
    scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    return ScanMetadata(
        file_name=file_name,
        size_bytes=path.stat().st_size,
        sha256=digest.hexdigest(),
        scanned_at_utc=scanned_at.replace("+00:00", "Z"),
    )
