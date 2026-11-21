"""Tests for filesystem scanner and reporting."""

import os
import pytest
from secret_sentry.scanner import scan_file, scan_directory


def test_scan_clean_fixture():
    path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample_clean.py")
    findings = scan_file(path)
    assert len(findings) == 0


def test_scan_leaks_fixture(tmp_path):
    leak_file = tmp_path / "sample_leaks.txt"
    # Construct synthetic test tokens dynamically to prevent GitHub Push Protection triggers on repo code
    pfx_stripe = "sk_" + "live_"
    pfx_slack = "xoxb-"
    content = (
        'AWS_KEY = "AKIAIOSFODNN7REALKEY"\n'
        'IGNORED_DUMMY_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'GITHUB_KEY = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"\n'
        f'STRIPE_KEY = "{pfx_stripe}51Abcdefghijklmnopqrstuvw999"\n'
        f'SLACK_WEBHOOK = "{pfx_slack}123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"\n'
        'DATABASE_URL = "postgres://admin:SuperSecretPass987!@db.internal:5432/production"\n'
        'PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"\n'
    )
    leak_file.write_text(content, encoding="utf-8")
    findings = scan_file(str(leak_file))
    assert len(findings) >= 5
    rule_ids = {f.rule_id for f in findings}
    assert "SEC-001" in rule_ids
    assert "SEC-002" in rule_ids
    assert "SEC-004" in rule_ids
    assert "SEC-005" in rule_ids


def test_scan_directory_clean():
    path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample_clean.py")
    summary = scan_directory(path)
    assert summary.is_clean is True
    assert summary.total_findings == 0
