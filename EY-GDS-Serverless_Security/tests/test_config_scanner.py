import pytest

from config_scanner.config_scanner import scan_configuration


def test_public_s3_bucket_is_detected():
    configuration = {
        "s3_buckets": [
            {
                "name": "public-bucket",
                "public": True,
                "encryption_enabled": True,
            }
        ]
    }

    findings = scan_configuration(configuration)

    assert any(
        finding.severity == "CRITICAL"
        and finding.scanner == "config_scanner"
        for finding in findings
    )


def test_unencrypted_s3_bucket_is_detected():
    configuration = {
        "s3_buckets": [
            {
                "name": "unencrypted-bucket",
                "public": False,
                "encryption_enabled": False,
            }
        ]
    }

    findings = scan_configuration(configuration)

    assert any(
        finding.severity == "HIGH"
        for finding in findings
    )


def test_lambda_logging_is_detected():
    configuration = {
        "lambda_functions": [
            {
                "name": "test-function",
                "logging_enabled": False,
                "environment_encryption_enabled": True,
            }
        ]
    }

    findings = scan_configuration(configuration)

    assert any(
        finding.severity == "MEDIUM"
        for finding in findings
    )


def test_lambda_environment_encryption_is_detected():
    configuration = {
        "lambda_functions": [
            {
                "name": "test-function",
                "logging_enabled": True,
                "environment_encryption_enabled": False,
            }
        ]
    }

    findings = scan_configuration(configuration)

    assert any(
        finding.severity == "HIGH"
        for finding in findings
    )


def test_api_without_authentication_is_detected():
    configuration = {
        "api_gateways": [
            {
                "name": "public-api",
                "authentication": "NONE",
            }
        ]
    }

    findings = scan_configuration(configuration)

    assert any(
        finding.severity == "HIGH"
        for finding in findings
    )


def test_secure_configuration_has_no_findings():
    configuration = {
        "s3_buckets": [
            {
                "name": "secure-bucket",
                "public": False,
                "encryption_enabled": True,
            }
        ],
        "lambda_functions": [
            {
                "name": "secure-function",
                "logging_enabled": True,
                "environment_encryption_enabled": True,
            }
        ],
        "api_gateways": [
            {
                "name": "secure-api",
                "authentication": "IAM",
            }
        ],
    }

    findings = scan_configuration(configuration)

    assert findings == []


def test_invalid_configuration_raises_error():
    with pytest.raises(ValueError):
        scan_configuration("invalid configuration")


def test_api_authentication_check_is_case_insensitive():
    configuration = {
        "api_gateways": [
            {
                "name": "public-api",
                "authentication": "none",
            }
        ]
    }

    findings = scan_configuration(configuration)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].scanner == "config_scanner"


def test_s3_bucket_can_have_multiple_findings():
    configuration = {
        "s3_buckets": [
            {
                "name": "insecure-bucket",
                "public": True,
                "encryption_enabled": False,
            }
        ]
    }

    findings = scan_configuration(configuration)

    assert len(findings) == 2

    severities = {
        finding.severity
        for finding in findings
    }

    assert severities == {"CRITICAL", "HIGH"}


def test_multiple_resource_types_are_scanned():
    configuration = {
        "s3_buckets": [
            {
                "name": "bad-bucket",
                "public": True,
                "encryption_enabled": False,
            }
        ],
        "lambda_functions": [
            {
                "name": "bad-function",
                "logging_enabled": False,
                "environment_encryption_enabled": False,
            }
        ],
        "api_gateways": [
            {
                "name": "bad-api",
                "authentication": "NONE",
            }
        ],
    }

    findings = scan_configuration(configuration)

    assert len(findings) == 5


def test_invalid_s3_configuration_raises_error():
    configuration = {
        "s3_buckets": "not a list",
    }

    with pytest.raises(ValueError):
        scan_configuration(configuration)