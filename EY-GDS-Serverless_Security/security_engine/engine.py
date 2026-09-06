from attack_detection.detector import detect_attacks
from config_scanner.config_scanner import scan_configuration
from dependency_scanner.scanner import scan_dependencies
from iam_scanner.scanner import scan_policy


def run_security_scan(
    requirements_file: str,
    event: dict,
    iam_policy: dict,
    configuration: dict,
):
    """
    Run all available security scanners.

    Returns:
        A combined list of security findings.
    """

    findings = []

    # Run dependency scanner
    dependency_findings = scan_dependencies(requirements_file)
    findings.extend(dependency_findings)

    # Run attack detection
    attack_findings = detect_attacks(event)
    findings.extend(attack_findings)

    # Run IAM scanner
    iam_findings = scan_policy(iam_policy)
    findings.extend(iam_findings)

    # Run configuration scanner
    config_findings = scan_configuration(configuration)
    findings.extend(config_findings)

    return findings


def summarize_findings(findings):
    """
    Summarize findings by severity.

    Returns:
        A dictionary containing the total number of findings
        and counts for each severity.
    """

    summary = {
        "total": len(findings),
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = finding.severity.upper()

        if severity in summary:
            summary[severity] += 1

    return summary