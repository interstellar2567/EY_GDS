from security_engine.engine import run_security_scan
from security_engine.engine import summarize_findings


SAMPLE_IAM_POLICY = {
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example-bucket/*",
    }
}

SAMPLE_CONFIGURATION = {
    "s3_buckets": [],
    "lambda_functions": [],
    "api_gateways": [],
}


def test_security_engine_detects_attack():
    event = {
        "ip": "192.168.1.100",
        "method": "GET",
        "path": "/users",
        "query": "id=1' OR '1'='1",
        "body": "",
        "user_agent": "Mozilla/5.0",
    }

    findings = run_security_scan(
        "requirements.txt",
        event,
        SAMPLE_IAM_POLICY,
        SAMPLE_CONFIGURATION,
    )

    attack_findings = [
        finding
        for finding in findings
        if finding.scanner == "attack_detection"
    ]

    assert len(attack_findings) >= 1


def test_security_engine_runs_all_scanners():
    event = {
        "ip": "192.168.1.100",
        "method": "TRACE",
        "path": "/download",
        "query": "file=../../../../etc/passwd",
        "body": "id=1' OR '1'='1",
        "user_agent": "Mozilla/5.0",
    }

    iam_policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
        }
    }

    configuration = {
        "s3_buckets": [
            {
                "name": "public-bucket",
                "public": True,
                "encryption_enabled": False,
            }
        ],
        "lambda_functions": [],
        "api_gateways": [],
    }

    findings = run_security_scan(
        "requirements.txt",
        event,
        iam_policy,
        configuration,
    )

    scanners = {
        finding.scanner
        for finding in findings
    }

    assert "attack_detection" in scanners
    assert "iam_scanner" in scanners
    assert "config_scanner" in scanners

def test_summarize_findings():
    event = {
        "ip": "192.168.1.100",
        "method": "TRACE",
        "path": "/users",
        "query": "id=1' OR '1'='1",
        "body": "",
        "user_agent": "Mozilla/5.0",
    }

    findings = run_security_scan(
        "requirements.txt",
        event,
        SAMPLE_IAM_POLICY,
        SAMPLE_CONFIGURATION,
    )

    summary = summarize_findings(findings)

    assert summary["total"] == len(findings)
    assert summary["HIGH"] >= 1
    assert summary["MEDIUM"] >= 1