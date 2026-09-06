# EY GDS Serverless Security

A Python-based security scanning framework for serverless and API environments.

The project combines multiple security scanners into a single security engine and provides a Streamlit dashboard for viewing security findings.

## Features

The project currently includes four security scanners:

### 1. Attack Detection

Detects suspicious API/serverless request patterns including:

- SQL injection
- Command injection
- Path traversal
- Suspicious HTTP methods such as `TRACE` and `CONNECT`

### 2. Dependency Scanner

Uses `pip-audit` to identify known vulnerabilities in Python dependencies defined in a `requirements.txt` file.

The scanner reports:

- Vulnerable package
- Installed version
- Vulnerability ID
- Vulnerability description
- Recommended fixed versions when available

### 3. IAM Scanner

Analyzes AWS IAM policies for excessive or dangerous permissions.

The scanner detects:

- Wildcard IAM actions
- Full IAM permissions
- High-risk IAM actions such as `iam:PassRole`
- Wildcard service permissions
- Wildcard resources

Findings are categorized by severity.

### 4. Configuration Scanner

Checks serverless/cloud configuration for common security misconfigurations.

Currently checks:

- Public S3 buckets
- S3 bucket encryption
- Lambda logging
- Lambda environment encryption
- API Gateway authentication

## Security Engine

The security engine combines all scanner results into a single list of findings.

The execution flow is:

```text
                   Security Engine
                         |
        +----------------+----------------+
        |                |                |
        v                v                v
 Dependency        Attack Detection    IAM Scanner
 Scanner                                 |
        |                                 |
        +----------------+----------------+
                         |
                         v
                Configuration Scanner
                         |
                         v
                 Combined Findings
                         |
                         v
                 Security Summary

PROJECT STRUCTURE:
EY-GDS-Serverless_Security/
│
├── attack_detection/
│   ├── __init__.py
│   ├── detector.py
│   └── rules.py
│
├── config_scanner/
│   ├── __init__.py
│   ├── checks.py
│   └── config_scanner.py
│
├── dependency_scanner/
│   ├── __init__.py
│   └── scanner.py
│
├── iam_scanner/
│   ├── __init__.py
│   ├── aws_iam.py
│   ├── rules.py
│   └── scanner.py
│
├── security_engine/
│   ├── __init__.py
│   └── engine.py
│
├── common/
│   └── finding.py
│
├── dashboard/
│   └── app.py
│
├── tests/
│   ├── test_attack_detection.py
│   ├── test_config_scanner.py
│   ├── test_dependency_scanner.py
│   ├── test_iam_scanner.py
│   └── test_security_engine.py
│
├── test_data/
│   └── vulnerable_requirements.txt
│
├── requirements.txt
├── README.md
└── .gitignore