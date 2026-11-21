"""Integration tests for Secret Sentry CLI."""

import os
import json
from secret_sentry.cli import main


def test_cli_scan_clean_exit_zero():
    clean_path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample_clean.py")
    code = main(["scan", clean_path])
    assert code == 0


def test_cli_scan_leaks_exit_one_on_strict(tmp_path):
    leak_file = tmp_path / "sample_leaks.txt"
    pfx_stripe = "sk_" + "live_"
    content = (
        'AWS_KEY = "AKIAIOSFODNN7REALKEY"\n'
        f'STRIPE_KEY = "{pfx_stripe}51Abcdefghijklmnopqrstuvw999"\n'
    )
    leak_file.write_text(content, encoding="utf-8")
    code = main(["scan", str(leak_file), "--strict"])
    assert code == 1


def test_cli_json_export_structure(capsys):
    clean_path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample_clean.py")
    code = main(["scan", clean_path, "--format", "json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["is_clean"] is True
    assert "files_scanned" in data
