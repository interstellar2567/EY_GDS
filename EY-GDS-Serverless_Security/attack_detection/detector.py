"""
Rule-based attack detection for serverless/API events.
"""

from typing import Any
from urllib.parse import unquote

from common.finding import Finding
from dependency_scanner.scanner import scan_dependencies

from .rules import (
    COMMAND_INJECTION_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    SQL_INJECTION_PATTERNS,
    SUSPICIOUS_HTTP_METHODS,
)


def _event_text(event: dict[str, Any]) -> str:
    """
    Combine user-controlled request fields into one searchable string.

    URL-decodes common request data before applying detection rules.
    """

    fields = [
        event.get("path", ""),
        event.get("query", ""),
        event.get("body", ""),
        event.get("user_agent", ""),
    ]

    text = " ".join(str(value) for value in fields)

    return unquote(text).lower()


def _find_matching_pattern(
    text: str,
    patterns: list[str],
) -> str | None:
    """Return the first matching pattern, or None."""

    for pattern in patterns:
        if pattern.lower() in text:
            return pattern

    return None


def detect_sql_injection(event: dict[str, Any]) -> Finding | None:
    """Detect common SQL injection patterns."""

    text = _event_text(event)

    matched_pattern = _find_matching_pattern(
        text,
        SQL_INJECTION_PATTERNS,
    )

    if matched_pattern is None:
        return None

    return Finding(
        scanner="attack_detection",
        severity="HIGH",
        title="Possible SQL injection attack",
        description=(
            "The request contains a pattern commonly associated "
            "with SQL injection."
        ),
        resource=event.get("path", "unknown"),
        recommendation=(
            "Use parameterized queries, validate user input, "
            "and avoid constructing SQL statements from raw input."
        ),
        evidence=f"Matched pattern: {matched_pattern}",
    )


def detect_command_injection(event: dict[str, Any]) -> Finding | None:
    """Detect common command injection patterns."""

    text = _event_text(event)

    matched_pattern = _find_matching_pattern(
        text,
        COMMAND_INJECTION_PATTERNS,
    )

    if matched_pattern is None:
        return None

    return Finding(
        scanner="attack_detection",
        severity="CRITICAL",
        title="Possible command injection attack",
        description=(
            "The request contains a pattern commonly associated "
            "with operating-system command injection."
        ),
        resource=event.get("path", "unknown"),
        recommendation=(
            "Avoid passing user-controlled input to shell commands. "
            "Use safe APIs, strict allowlists, and input validation."
        ),
        evidence=f"Matched pattern: {matched_pattern}",
    )


def detect_path_traversal(event: dict[str, Any]) -> Finding | None:
    """Detect directory traversal patterns."""

    text = _event_text(event)

    matched_pattern = _find_matching_pattern(
        text,
        PATH_TRAVERSAL_PATTERNS,
    )

    if matched_pattern is None:
        return None

    return Finding(
        scanner="attack_detection",
        severity="HIGH",
        title="Possible path traversal attack",
        description=(
            "The request contains a directory traversal pattern "
            "that may be attempting to access files outside the "
            "intended directory."
        ),
        resource=event.get("path", "unknown"),
        recommendation=(
            "Normalize and validate file paths and restrict file "
            "access to an approved directory."
        ),
        evidence=f"Matched pattern: {matched_pattern}",
    )


def detect_suspicious_method(
    event: dict[str, Any],
) -> Finding | None:
    """Detect suspicious HTTP methods."""

    method = str(event.get("method", "")).upper()

    if method not in SUSPICIOUS_HTTP_METHODS:
        return None

    return Finding(
        scanner="attack_detection",
        severity="MEDIUM",
        title="Suspicious HTTP method",
        description=(
            f"The request uses the HTTP method '{method}', "
            "which is not normally required by a typical API."
        ),
        resource=event.get("path", "unknown"),
        recommendation=(
            "Allow only the HTTP methods required by the API "
            "and disable unnecessary methods."
        ),
        evidence=f"HTTP method: {method}",
    )


def detect_attacks(event: dict[str, Any]) -> list[Finding]:
    """
    Run all attack-detection rules against an event.

    Returns:
        A list of Finding objects.
    """

    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    findings: list[Finding] = []

    detectors = [
        detect_sql_injection,
        detect_command_injection,
        detect_path_traversal,
        detect_suspicious_method,
    ]

    for detector in detectors:
        finding = detector(event)

        if finding is not None:
            findings.append(finding)

    return findings

def test_incomplete_event_does_not_crash():
    event = {
        "method": "GET",
    }

    findings = detect_attacks(event)

    assert findings == []


def test_empty_pip_audit_output():
    mock_result = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="",
        stderr="pip-audit failed",
    )

    with patch(
        "dependency_scanner.scanner.subprocess.run",
        return_value=mock_result,
    ):
        with pytest.raises(RuntimeError):
            scan_dependencies("requirements.txt")