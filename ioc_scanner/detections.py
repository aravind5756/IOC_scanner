"""Behavioural detection rules for suspicious log activity."""

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .engine import is_valid_ipv4

IPV4_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
FAILED_LOGIN_TERMS = ("failed login", "failed password")
SUCCESSFUL_LOGIN_TERMS = ("successful login", "accepted password", "logged in")
TIMESTAMP_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})?)"
)


@dataclass(frozen=True)
class SecurityAlert:
    """A suspicious behaviour detected across multiple log entries."""

    rule_id: str
    title: str
    severity: str
    source_ip: str
    occurrences: int
    evidence_lines: tuple[int, ...]
    window_minutes: int | None


def parse_log_timestamp(line: str) -> datetime | None:
    """Parse an ISO-style timestamp from the beginning of a log line."""
    match = TIMESTAMP_PATTERN.match(line)
    if not match:
        return None

    timestamp_text = match.group("timestamp")
    if timestamp_text.endswith("Z"):
        timestamp_text = f"{timestamp_text[:-1]}+00:00"

    try:
        timestamp = datetime.fromisoformat(timestamp_text)
    except ValueError:
        return None

    if timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
    return timestamp


def busiest_attempt_window(
    attempts: list[tuple[int, datetime]], window_minutes: int
) -> list[tuple[int, datetime]]:
    """Return the largest group of attempts inside a rolling time window."""
    ordered_attempts = sorted(attempts, key=lambda attempt: attempt[1])
    window = timedelta(minutes=window_minutes)
    window_start = 0
    busiest: list[tuple[int, datetime]] = []

    for window_end, (_, end_time) in enumerate(ordered_attempts):
        while end_time - ordered_attempts[window_start][1] > window:
            window_start += 1
        candidate = ordered_attempts[window_start : window_end + 1]
        if len(candidate) > len(busiest):
            busiest = candidate

    return busiest


def detect_repeated_failed_logins(
    lines: Iterable[str], threshold: int = 5, window_minutes: int = 5
) -> list[SecurityAlert]:
    """Detect IP addresses responsible for repeated failed login events."""
    if threshold < 1:
        raise ValueError("The failed-login threshold must be at least 1.")
    if window_minutes < 1:
        raise ValueError("The failed-login window must be at least 1 minute.")

    attempts_by_ip: defaultdict[str, list[tuple[int, datetime | None]]] = defaultdict(
        list
    )

    for line_number, line in enumerate(lines, start=1):
        normalised_line = line.lower()
        if not any(term in normalised_line for term in FAILED_LOGIN_TERMS):
            continue

        addresses = {
            candidate
            for candidate in re.findall(IPV4_PATTERN, line)
            if is_valid_ipv4(candidate)
        }
        timestamp = parse_log_timestamp(line)
        for address in addresses:
            attempts_by_ip[address].append((line_number, timestamp))

    alerts = []
    for address, attempts in sorted(attempts_by_ip.items()):
        timestamps_available = all(timestamp is not None for _, timestamp in attempts)
        if timestamps_available:
            timed_attempts = [
                (line_number, timestamp)
                for line_number, timestamp in attempts
                if timestamp is not None
            ]
            evidence_attempts = busiest_attempt_window(timed_attempts, window_minutes)
            alert_window = window_minutes
        else:
            evidence_attempts = attempts
            alert_window = None

        if len(evidence_attempts) < threshold:
            continue

        evidence_lines = tuple(sorted(line_number for line_number, _ in evidence_attempts))

        alerts.append(
            SecurityAlert(
                rule_id="AUTH-001",
                title="Repeated failed login attempts",
                severity="high",
                source_ip=address,
                occurrences=len(evidence_lines),
                evidence_lines=evidence_lines,
                window_minutes=alert_window,
            )
        )

    return alerts


def detect_success_after_failed_logins(
    lines: Iterable[str], threshold: int = 5, window_minutes: int = 5
) -> list[SecurityAlert]:
    """Detect successful logins that follow repeated failures from one IP."""
    if threshold < 1:
        raise ValueError("The failed-login threshold must be at least 1.")
    if window_minutes < 1:
        raise ValueError("The failed-login window must be at least 1 minute.")

    events_by_ip: defaultdict[str, list[tuple[int, datetime, str]]] = defaultdict(list)

    for line_number, line in enumerate(lines, start=1):
        timestamp = parse_log_timestamp(line)
        if timestamp is None:
            continue

        normalised_line = line.lower()
        if any(term in normalised_line for term in FAILED_LOGIN_TERMS):
            event_type = "failure"
        elif any(term in normalised_line for term in SUCCESSFUL_LOGIN_TERMS):
            event_type = "success"
        else:
            continue

        addresses = {
            candidate
            for candidate in re.findall(IPV4_PATTERN, line)
            if is_valid_ipv4(candidate)
        }
        for address in addresses:
            events_by_ip[address].append((line_number, timestamp, event_type))

    alerts = []
    window = timedelta(minutes=window_minutes)
    for address, events in sorted(events_by_ip.items()):
        failures: list[tuple[int, datetime]] = []
        for line_number, timestamp, event_type in sorted(
            events, key=lambda event: event[1]
        ):
            if event_type == "failure":
                failures.append((line_number, timestamp))
                continue

            recent_failures = [
                failure
                for failure in failures
                if timestamp - failure[1] <= window
            ]
            if len(recent_failures) < threshold:
                continue

            evidence_lines = tuple(
                sorted([failure[0] for failure in recent_failures] + [line_number])
            )
            alerts.append(
                SecurityAlert(
                    rule_id="AUTH-002",
                    title="Successful login following repeated failures",
                    severity="critical",
                    source_ip=address,
                    occurrences=len(recent_failures),
                    evidence_lines=evidence_lines,
                    window_minutes=window_minutes,
                )
            )
            break

    return alerts
