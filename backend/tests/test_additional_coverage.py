from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.scan import Scan
from app.models.user import Role, User
from app.models.vulnerability import Vulnerability
from app.models.workspace import Workspace
from app.services.rate_limit_service import RateLimitService
from app.services.scanning_service import CounterLike, ScanningService


def _register_and_login(client: TestClient, *, email: str, role: str = "security_analyst") -> dict[str, str]:
    register = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "StrongPassw0rd!", "role": role},
    )
    assert register.status_code == 200
    login = client.post("/api/v1/auth/login", json={"email": email, "password": "StrongPassw0rd!"})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_ai_endpoints_return_404_for_missing_resources(client: TestClient) -> None:
    headers = _register_and_login(client, email="ai-missing@example.com", role="viewer")

    missing_finding = client.get("/api/v1/ai/findings/999999/insight", headers=headers)
    assert missing_finding.status_code == 404
    assert missing_finding.json()["detail"] == "Vulnerability not found"

    missing_scan = client.get("/api/v1/ai/scans/999999/executive-summary", headers=headers)
    assert missing_scan.status_code == 404
    assert missing_scan.json()["detail"] == "Scan not found"


def test_scanning_endpoints_return_404_for_missing_resources(client: TestClient) -> None:
    headers = _register_and_login(client, email="scan-missing@example.com")

    missing_job = client.get("/api/v1/scanning/jobs/999999", headers=headers)
    assert missing_job.status_code == 404
    assert missing_job.json()["detail"] == "Scan job not found"

    assert client.get("/api/v1/scanning/999999/diff", headers=headers).status_code == 404
    assert (
        client.post(
            "/api/v1/scanning/999999/policy-gate",
            headers=headers,
            json={"max_allowed_severity": "medium", "fail_on_open": True},
        ).status_code
        == 404
    )
    assert client.get("/api/v1/scanning/999999/reports/json", headers=headers).status_code == 404
    assert client.get("/api/v1/scanning/999999/reports/sarif", headers=headers).status_code == 404
    assert client.get("/api/v1/scanning/999999/remediation-checklist", headers=headers).status_code == 404
    assert client.get("/api/v1/scanning/999999/suppressions", headers=headers).status_code == 404


def test_devsecops_upload_scan_normalizes_profile_and_snippet_type(client: TestClient) -> None:
    headers = _register_and_login(client, email="upload@example.com")

    response = client.post(
        "/api/v1/scanning/devsecops/upload",
        headers=headers,
        data={
            "target": "https://repo.example.org/service-a",
            "snippet_type": "yaml",
            "profile": "invalid-profile",
        },
        files={"file": ("snippet.txt", b"' OR 1=1 -- <script>alert(1)</script>", "text/plain")},
    )
    assert response.status_code == 200

    body = response.json()
    assert body["target"] == "https://repo.example.org/service-a#code"
    assert body["profile"] == "deep"


def test_rate_limit_service_enforces_threshold_and_evicts_old_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    host = "203.0.113.10"

    class _Client:
        def __init__(self, host_value: str) -> None:
            self.host = host_value

    class _Request:
        def __init__(self, host_value: str) -> None:
            self.client = _Client(host_value)

    class _FakeDateTime:
        current = datetime(2026, 1, 1, tzinfo=UTC)

        @classmethod
        def now(cls, _tz=UTC) -> datetime:
            return cls.current

    request = _Request(host)
    monkeypatch.setattr(settings, "auth_rate_limit_per_minute", 2)
    monkeypatch.setattr(RateLimitService, "_hits", defaultdict(deque))
    monkeypatch.setattr("app.services.rate_limit_service.datetime", _FakeDateTime)

    RateLimitService.check_auth_rate_limit(request)
    _FakeDateTime.current += timedelta(seconds=1)
    RateLimitService.check_auth_rate_limit(request)
    _FakeDateTime.current += timedelta(seconds=1)
    with pytest.raises(HTTPException) as exc:
        RateLimitService.check_auth_rate_limit(request)
    assert exc.value.status_code == 429

    _FakeDateTime.current += timedelta(seconds=61)
    RateLimitService.check_auth_rate_limit(request)


def test_scanning_service_remediation_checklist_and_counterlike(db_session: Session) -> None:
    workspace = Workspace(name="workspace-extra", slug="workspace-extra")
    db_session.add(workspace)
    db_session.flush()

    user = User(
        workspace_id=workspace.id,
        email="coverage-user@example.com",
        hashed_password="hashed",
        role=Role.security_analyst,
    )
    db_session.add(user)
    db_session.flush()

    scan = Scan(
        workspace_id=workspace.id,
        target="https://repo.example.org",
        payload="payload",
        requested_by_user_id=user.id,
        status="completed",
        profile="deep",
        started_at=datetime.now(UTC) - timedelta(seconds=3),
        completed_at=datetime.now(UTC),
        duration_ms=300,
    )
    db_session.add(scan)
    db_session.flush()

    vuln_a = Vulnerability(
        workspace_id=workspace.id,
        scan_id=scan.id,
        rule_key="SECRET_DETECTION",
        severity="high",
        confidence=0.95,
        reason_code="RC1",
        owasp_category="A05:2021-Security Misconfiguration",
        cwe_id="CWE-200",
        title="Leaked secret",
        evidence="token=secret",
        remediation="Rotate token",
        secure_example="use env vars",
        dedupe_key="secret-1",
        status="open",
    )
    vuln_b = Vulnerability(
        workspace_id=workspace.id,
        scan_id=scan.id,
        rule_key="SENSITIVE_DATA_EXPOSURE",
        severity="medium",
        confidence=0.9,
        reason_code="RC2",
        owasp_category="A05:2021-Security Misconfiguration",
        cwe_id="CWE-532",
        title="Sensitive data exposed",
        evidence="password in logs",
        remediation="Mask sensitive values",
        secure_example="logging filter",
        dedupe_key="sensitive-1",
        status="open",
    )
    db_session.add_all([vuln_a, vuln_b])
    db_session.commit()

    checklist = ScanningService.build_remediation_checklist(db_session, workspace_id=workspace.id, scan_id=scan.id)
    assert checklist is not None
    assert checklist.scan_id == scan.id
    assert any("Fix SECRET_DETECTION" in task for task in checklist.checklist)
    secret_guidance = [task for task in checklist.checklist if "secret scanning coverage" in task.lower()]
    config_guidance = [task for task in checklist.checklist if "policy checks in ci" in task.lower()]
    assert len(secret_guidance) == 1
    assert len(config_guidance) == 1

    assert (
        ScanningService.build_remediation_checklist(db_session, workspace_id=workspace.id, scan_id=999999) is None
    )

    summary = CounterLike.count_severity([vuln_a, vuln_b])
    assert summary == {"low": 0, "medium": 1, "high": 1, "critical": 0}
