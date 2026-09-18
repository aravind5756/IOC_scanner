"""Behavioural detection rules for suspicious log activity."""

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from .engine import is_valid_ipv4

IPV4_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
FAILED_LOGIN_TERMS = ("failed login", "failed password")


@dataclass(frozen=True)
class SecurityAlert:
    """A suspicious behaviour detected across multiple log entries."""

    rule_id: str
    title: str
    severity: str
    source_ip: str
    occurrences: int
    evidence_lines: tuple[int, ...]


def detect_repeated_failed_logins(
    lines: Iterable[str], threshold: int = 5
) -> list[SecurityAlert]:
    """Detect IP addresses responsible for repeated failed login events."""
    if threshold < 1:
        raise ValueError("The failed-login threshold must be at least 1.")

    attempts_by_ip: defaultdict[str, list[int]] = defaultdict(list)

    for line_number, line in enumerate(lines, start=1):
        normalised_line = line.lower()
        if not any(term in normalised_line for term in FAILED_LOGIN_TERMS):
            continue

        addresses = {
            candidate
            for candidate in re.findall(IPV4_PATTERN, line)
            if is_valid_ipv4(candidate)
        }
        for address in addresses:
            attempts_by_ip[address].append(line_number)

    alerts = []
    for address, evidence_lines in sorted(attempts_by_ip.items()):
        if len(evidence_lines) < threshold:
            continue

        alerts.append(
            SecurityAlert(
                rule_id="AUTH-001",
                title="Repeated failed login attempts",
                severity="high",
                source_ip=address,
                occurrences=len(evidence_lines),
                evidence_lines=tuple(evidence_lines),
            )
        )

    return alerts
