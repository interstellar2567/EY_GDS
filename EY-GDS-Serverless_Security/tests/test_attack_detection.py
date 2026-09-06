import pytest
from attack_detection.detector import detect_attacks



def test_normal_request_has_no_findings():
    event = {
        "ip": "192.168.1.10",
        "method": "GET",
        "path": "/users",
        "query": "id=123",
        "body": "",
        "user_agent": "Mozilla/5.0",
    }

    findings = detect_attacks(event)

    assert findings == []


def test_sql_injection_is_detected():
    event = {
        "ip": "192.168.1.20",
        "method": "GET",
        "path": "/users",
        "query": "id=1' OR '1'='1",
        "body": "",
        "user_agent": "Mozilla/5.0",
    }

    findings = detect_attacks(event)

    assert len(findings) == 1
    assert findings[0].scanner == "attack_detection"
    assert findings[0].severity == "HIGH"
    assert "SQL injection" in findings[0].title


def test_command_injection_is_detected():
    event = {
        "ip": "192.168.1.30",
        "method": "GET",
        "path": "/ping",
        "query": "host=8.8.8.8;whoami",
        "body": "",
        "user_agent": "Mozilla/5.0",
    }

    findings = detect_attacks(event)

    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "command injection" in findings[0].title


def test_path_traversal_is_detected():
    event = {
        "ip": "192.168.1.40",
        "method": "GET",
        "path": "/download",
        "query": "file=../../../../etc/passwd",
        "body": "",
        "user_agent": "Mozilla/5.0",
    }

    findings = detect_attacks(event)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "path traversal" in findings[0].title


def test_suspicious_http_method_is_detected():
    event = {
        "ip": "192.168.1.50",
        "method": "TRACE",
        "path": "/api/users",
        "query": "",
        "body": "",
        "user_agent": "Mozilla/5.0",
    }

    findings = detect_attacks(event)

    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "HTTP method" in findings[0].title


def test_multiple_attack_types_are_detected():
    event = {
        "ip": "192.168.1.60",
        "method": "TRACE",
        "path": "/download",
        "query": "file=../../../../etc/passwd",
        "body": "id=1' OR '1'='1",
        "user_agent": "Mozilla/5.0",
    }

    findings = detect_attacks(event)

    assert len(findings) >= 3


def test_invalid_event_raises_error():
    invalid_event = "this is not a dictionary"

    with pytest.raises(TypeError):
        detect_attacks(invalid_event)

def test_encoded_path_traversal_is_detected():
    event = {
        "ip": "192.168.1.70",
        "method": "GET",
        "path": "/download",
        "query": "file=..%2F..%2F..%2Fetc%2Fpasswd",
        "body": "",
        "user_agent": "Mozilla/5.0",
    }

    findings = detect_attacks(event)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "path traversal" in findings[0].title

def test_encoded_sql_injection_is_detected():
    event = {
        "ip": "192.168.1.80",
        "method": "GET",
        "path": "/users",
        "query": "id=1%27%20OR%20%271%27%3D%271",
        "body": "",
        "user_agent": "Mozilla/5.0",
    }

    findings = detect_attacks(event)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "SQL injection" in findings[0].title