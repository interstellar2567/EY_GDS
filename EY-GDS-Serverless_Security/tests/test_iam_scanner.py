import pytest

from iam_scanner.scanner import scan_policy


def test_normal_policy_has_no_findings():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::example-bucket/*",
        }
    }

    findings = scan_policy(policy)

    assert findings == []


def test_wildcard_action_is_critical():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
    }

    findings = scan_policy(policy)

    assert len(findings) == 2

    action_findings = [
        finding
        for finding in findings
        if "action" in finding.evidence.lower()
    ]

    assert len(action_findings) == 1
    assert action_findings[0].severity == "CRITICAL"
    assert action_findings[0].scanner == "iam_scanner"


def test_iam_wildcard_is_critical():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": "*",
        }
    }

    findings = scan_policy(policy)

    assert any(
        finding.severity == "CRITICAL"
        for finding in findings
    )


def test_high_risk_iam_action_is_detected():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::123456789012:role/example",
        }
    }

    findings = scan_policy(policy)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].scanner == "iam_scanner"


def test_wildcard_service_action_is_high():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::example-bucket/*",
        }
    }

    findings = scan_policy(policy)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_wildcard_resource_is_medium():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
        }
    }

    findings = scan_policy(policy)

    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"


def test_statement_list_is_supported():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
            },
        ]
    }

    findings = scan_policy(policy)

    assert len(findings) == 4


def test_deny_statement_is_ignored():
    policy = {
        "Statement": {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        }
    }

    findings = scan_policy(policy)

    assert findings == []


def test_invalid_policy_raises_error():
    with pytest.raises(TypeError):
        scan_policy("not a dictionary")

def test_action_list_is_supported():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
            ],
            "Resource": "arn:aws:s3:::example-bucket/*",
        }
    }

    findings = scan_policy(policy)

    assert findings == []

def test_resource_list_is_supported():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": [
                "arn:aws:s3:::bucket-one/*",
                "arn:aws:s3:::bucket-two/*",
            ],
        }
    }

    findings = scan_policy(policy)

    assert findings == []

def test_iam_action_matching_is_case_insensitive():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "IAM:PASSROLE",
            "Resource": "arn:aws:iam::123456789012:role/example",
        }
    }

    findings = scan_policy(policy)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].scanner == "iam_scanner"


def test_multiple_actions_are_scanned():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "iam:PassRole",
                "iam:CreateRole",
            ],
            "Resource": "*",
        }
    }

    findings = scan_policy(policy)

    assert len(findings) == 3

def test_safe_iam_action_has_no_findings():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "iam:GetRole",
            "Resource": "arn:aws:iam::123456789012:role/example",
        }
    }

    findings = scan_policy(policy)

    assert findings == []