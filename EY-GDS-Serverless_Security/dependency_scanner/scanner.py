import json
import subprocess
import sys
from pathlib import Path

from common.finding import Finding


def scan_dependencies(requirements_file: str):
    """Scan a requirements file for known vulnerabilities."""

    requirements_path = Path(requirements_file)

    if not requirements_path.exists():
        raise FileNotFoundError(
            f"Requirements file not found: {requirements_file}"
        )

    command = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(requirements_path),
        "-f",
        "json",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if not result.stdout.strip():
        raise RuntimeError(
            "pip-audit did not return any output.\n"
            f"Error: {result.stderr}"
        )

    try:
        audit_results = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Could not parse pip-audit output:\n{result.stdout}"
        ) from exc

    findings = []
    seen_vulnerabilities = set()

    for dependency in audit_results.get("dependencies", []):
        package_name = dependency.get("name", "Unknown package")
        package_version = dependency.get("version", "Unknown version")

        for vulnerability in dependency.get("vulns", []):
            vulnerability_id = vulnerability.get(
                "id",
                "Unknown ID"
            )

            # Prevent duplicate vulnerability findings.
            unique_key = (package_name, package_version, vulnerability_id)

            if unique_key in seen_vulnerabilities:
                continue

            seen_vulnerabilities.add(unique_key)

            description = vulnerability.get(
                "description",
                "A known vulnerability was found."
            )

            fix_versions = vulnerability.get("fix_versions", [])

            if fix_versions:
                recommendation = (
                    f"Upgrade {package_name} to one of: "
                    f"{', '.join(fix_versions)}"
                )
            else:
                recommendation = (
                    f"Review {vulnerability_id} and upgrade "
                    f"{package_name} when a fix is available."
                )

            finding = Finding(
                scanner="dependency_scanner",
                severity="UNKNOWN",
                title=f"Vulnerable dependency: {package_name}",
                description=description,
                resource=f"{package_name}=={package_version}",
                recommendation=recommendation,
                evidence=vulnerability_id,
            )

            findings.append(finding)

    return findings