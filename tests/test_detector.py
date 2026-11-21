"""Tests for secret detection patterns and allowlists."""

import pytest
from secret_sentry.detector import scan_line


def test_detect_aws_key():
    line = 'AWS_SECRET_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"'
    findings = scan_line(line, 1, "test.py")
    assert any(f.rule_id == "SEC-001" for f in findings)


def test_detect_github_token():
    line = 'GITHUB_AUTH_TOKEN="ghp_1234567890abcdefghijklmnopqrstuvwx"'
    findings = scan_line(line, 10, "test.py")
    assert any(f.rule_id == "SEC-002" for f in findings)


def test_detect_private_key_header():
    line = "-----BEGIN RSA PRIVATE KEY-----"
    findings = scan_line(line, 1, "key.pem")
    assert any(f.rule_id == "SEC-004" for f in findings)


def test_ignore_dummy_example_key():
    line = 'AWS_KEY = "AKIA1234567890EXAMPLE"'
    findings = scan_line(line, 1, "test.py")
    assert len(findings) == 0


def test_clean_line_no_findings():
    line = 'def calculate_sum(a, b): return a + b'
    findings = scan_line(line, 1, "math.py")
    assert len(findings) == 0
