"""Smoke tests for the top-level CLI scanner in scripts/scan.py.

These tests avoid the FastAPI/DB stack and only exercise the standalone
scanner engine, so they run in any environment that can import the engine
module directly.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from io import StringIO
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

_spec = importlib.util.spec_from_file_location("scan_cli", REPO_ROOT / "scripts" / "scan.py")
scan_cli = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(scan_cli)

SAMPLES = REPO_ROOT / "data" / "samples"


def _run(capsys, argv):
    rc = scan_cli.main(argv)
    out = capsys.readouterr().out
    return rc, out


def test_sqli_sample_flags_injection(capsys):
    rc, out = _run(capsys, [str(SAMPLES / "sqli_payload.txt")])
    assert rc == 0
    assert "SQLI" in out
    assert "A03:2021-Injection" in out


def test_xss_sample_flags_xss(capsys):
    rc, out = _run(capsys, [str(SAMPLES / "xss_payload.txt")])
    assert rc == 0
    assert "XSS" in out


def test_clean_sample_has_no_findings(capsys):
    rc, out = _run(capsys, [str(SAMPLES / "clean_request.txt")])
    assert rc == 0
    assert "No findings" in out


def test_json_output_is_valid_and_structured(capsys):
    rc, out = _run(capsys, ["--json", "--profile", "deep", str(SAMPLES / "insecure_config.yaml")])
    assert rc == 0
    data = json.loads(out)
    assert data["profile"] == "deep"
    assert data["summary"]["total"] >= 1
    assert any(f["rule_key"] == "SECRET_DETECTION" for f in data["findings"])


def test_fail_on_high_exits_nonzero_when_high_findings_present(capsys):
    rc, _ = _run(capsys, ["--fail-on", "high", str(SAMPLES / "sqli_payload.txt")])
    assert rc == 1


def test_fail_on_critical_zero_when_only_high_present(capsys):
    rc, _ = _run(capsys, ["--fail-on", "critical", str(SAMPLES / "sqli_payload.txt")])
    assert rc == 0


def test_stdin_input(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", StringIO("debug=true\ncors_allow_origins=['*']"))
    rc, out = _run(capsys, ["-"])
    assert rc == 0
    assert "INSECURE_CONFIG" in out


def test_missing_file_raises(capsys):
    with pytest.raises(SystemExit):
        scan_cli.main(["/tmp/does-not-exist.txt"])
