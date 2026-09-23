"""Report metadata helpers for identifying scanned evidence files."""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

HASH_CHUNK_SIZE = 64 * 1024


@dataclass(frozen=True)
class ScanMetadata:
    """Identifying information recorded for a scanned file."""

    file_name: str
    size_bytes: int
    sha256: str
    scanned_at_utc: str


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
