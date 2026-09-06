"""
IAM policy scanner.

Analyzes IAM policies for dangerous permissions and returns
findings using the project's common Finding model.
"""

from typing import Any

from common.finding import Finding

from iam_scanner.rules import check_action, check_resource


def scan_policy(policy: dict[str, Any]) -> list[Finding]:
    """
    Scan an IAM policy for risky permissions.

    Args:
        policy: IAM policy represented as a dictionary.

    Returns:
        A list of Finding objects.
    """

    if not isinstance(policy, dict):
        raise TypeError("policy must be a dictionary")

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        raise TypeError("Statement must be a dictionary or list")

    findings: list[Finding] = []

    for statement in statements:

        if not isinstance(statement, dict):
            continue

        # We only analyze Allow statements.
        effect = str(statement.get("Effect", "")).lower()

        if effect != "allow":
            continue

        actions = statement.get("Action", [])

        if isinstance(actions, str):
            actions = [actions]

        if not isinstance(actions, list):
            continue

        resources = statement.get("Resource", [])

        if isinstance(resources, str):
            resources = [resources]

        if not isinstance(resources, list):
            resources = []

        # Check actions
        for action in actions:

            result = check_action(str(action))

            if result is None:
                continue

            severity, description = result

            findings.append(
                Finding(
                    scanner="iam_scanner",
                    severity=severity,
                    title="Risky IAM action detected",
                    description=description,
                    resource=str(action),
                    recommendation=(
                        "Apply the principle of least privilege "
                        "and grant only the IAM actions required."
                    ),
                    evidence=f"Action: {action}",
                )
            )

        # Check resources
        for resource in resources:

            result = check_resource(str(resource))

            if result is None:
                continue

            severity, description = result

            findings.append(
                Finding(
                    scanner="iam_scanner",
                    severity=severity,
                    title="Wildcard IAM resource detected",
                    description=description,
                    resource=str(resource),
                    recommendation=(
                        "Replace wildcard resources with the "
                        "specific resources required by the policy."
                    ),
                    evidence=f"Resource: {resource}",
                )
            )

    return findings