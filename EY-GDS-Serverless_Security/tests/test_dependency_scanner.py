import pytest
import subprocess
from unittest.mock import patch
from dependency_scanner.scanner import scan_dependencies


def test_clean_requirements():
    findings = scan_dependencies("requirements.txt")

    assert findings == []


def test_vulnerable_requirements():
    findings = scan_dependencies(
        "test_data/vulnerable_requirements.txt"
    )

    assert len(findings) > 0


def test_finding_contains_required_information():
    findings = scan_dependencies(
        "test_data/vulnerable_requirements.txt"
    )

    finding = findings[0]

    assert finding.scanner == "dependency_scanner"
    assert finding.severity == "UNKNOWN"
    assert finding.title
    assert finding.description
    assert finding.resource
    assert finding.recommendation
    assert finding.evidence


def test_no_duplicate_vulnerabilities():
    findings = scan_dependencies(
        "test_data/vulnerable_requirements.txt"
    )

    finding_keys = [
        (
            finding.resource,
            finding.evidence,
        )
        for finding in findings
    ]

    assert len(finding_keys) == len(set(finding_keys))


def test_missing_requirements_file():
    with pytest.raises(FileNotFoundError):
        scan_dependencies("test_data/does_not_exist.txt")


def test_invalid_pip_audit_output():
    mock_result = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="this is not valid json",
        stderr="",
    )

    with patch(
        "dependency_scanner.scanner.subprocess.run",
        return_value=mock_result,
    ):
        with pytest.raises(RuntimeError):
            scan_dependencies("requirements.txt")


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