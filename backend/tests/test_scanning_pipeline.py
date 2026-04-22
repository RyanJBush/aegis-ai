from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def authenticate_analyst(client: TestClient) -> str:
    client.post(
        "/api/v1/auth/register",
        json={"email": "analyst@example.com", "password": "StrongPassw0rd!", "role": "security_analyst"},
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "StrongPassw0rd!"},
    )
    return login.json()["access_token"]


def test_scan_detects_sqli_and_xss_and_reports(client: TestClient) -> None:
    token = authenticate_analyst(client)

    payload = "' OR 1=1 -- <script>alert(1)</script>"
    scan_response = client.post(
        "/api/v1/scanning/run",
        headers={"Authorization": f"Bearer {token}"},
        json={"target": "https://app.local/login", "payload": payload},
    )
    assert scan_response.status_code == 200
    assert scan_response.json()["vulnerabilities_found"] >= 2

    list_response = client.get("/api/v1/vulnerabilities", headers={"Authorization": f"Bearer {token}"})
    assert list_response.status_code == 200
    assert len(list_response.json()) >= 2


def test_scan_profile_workflow_comments_and_risk_acceptance(client: TestClient) -> None:
    token = authenticate_analyst(client)
    scan_response = client.post(
        "/api/v1/scanning/run",
        headers={"Authorization": f"Bearer {token}"},
        json={"target": "https://svc.local", "payload": "debug=true md5(password)", "profile": "standard"},
    )
    assert scan_response.status_code == 200
    scan_id = scan_response.json()["id"]

    findings_response = client.get("/api/v1/vulnerabilities", headers={"Authorization": f"Bearer {token}"})
    findings = findings_response.json()
    vuln_id = findings[0]["id"]

    workflow_response = client.patch(
        f"/api/v1/vulnerabilities/{vuln_id}/workflow",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "triaged", "assigned_owner": "dev-team@app.local", "notes": "Investigating fix"},
    )
    assert workflow_response.status_code == 200

    comment_response = client.post(
        f"/api/v1/vulnerabilities/{vuln_id}/comments",
        headers={"Authorization": f"Bearer {token}"},
        json={"body": "Need patch this before release."},
    )
    assert comment_response.status_code == 200

    accept_response = client.post(
        f"/api/v1/vulnerabilities/{vuln_id}/risk-acceptance",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Compensating controls in place for internal-only environment."},
    )
    assert accept_response.status_code == 200
    assert accept_response.json()["status"] == "active"

    timeline_response = client.get(
        f"/api/v1/vulnerabilities/{vuln_id}/timeline",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert timeline_response.status_code == 200
    assert len(timeline_response.json()["events"]) >= 3

    review_response = client.patch(
        f"/api/v1/scanning/{scan_id}/status",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "reviewed"},
    )
    assert review_response.status_code == 200


def test_scan_diff_queue_policy_gate_and_trends(client: TestClient) -> None:
    token = authenticate_analyst(client)

    baseline = client.post(
        "/api/v1/scanning/run",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target": "https://svc.local",
            "payload": "' OR 1=1 -- <script>alert(1)</script>",
            "profile": "quick",
        },
    )
    baseline_id = baseline.json()["id"]

    queued = client.post(
        "/api/v1/scanning/queue",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target": "https://svc.local",
            "payload": "' OR 1=1 --",
            "profile": "quick",
            "baseline_scan_id": baseline_id,
        },
    )
    assert queued.status_code == 200
    assert queued.json()["status"] in {"completed", "running", "queued"}

    job_id = queued.json()["id"]
    job = client.get(f"/api/v1/scanning/jobs/{job_id}", headers={"Authorization": f"Bearer {token}"})
    assert job.status_code == 200
    current_scan_id = job.json()["scan_id"]

    diff_response = client.get(
        f"/api/v1/scanning/{current_scan_id}/diff",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert diff_response.status_code == 200
    assert diff_response.json()["resolved_findings"] >= 1

    json_report = client.get(
        f"/api/v1/scanning/{current_scan_id}/reports/json",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert json_report.status_code == 200
    assert json_report.json()["scan_id"] == current_scan_id

    sarif_report = client.get(
        f"/api/v1/scanning/{current_scan_id}/reports/sarif",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert sarif_report.status_code == 200
    assert sarif_report.json()["sarif"]["version"] == "2.1.0"

    gate = client.post(
        f"/api/v1/scanning/{current_scan_id}/policy-gate",
        headers={"Authorization": f"Bearer {token}"},
        json={"max_allowed_severity": "medium", "fail_on_open": True},
    )
    assert gate.status_code == 200
    assert "passed" in gate.json()

    suppressions = client.get(
        f"/api/v1/scanning/{current_scan_id}/suppressions",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert suppressions.status_code == 200

    trends = client.get("/api/v1/scanning/history/trends?days=14", headers={"Authorization": f"Bearer {token}"})
    assert trends.status_code == 200
    assert "points" in trends.json()

    ai_summary = client.get(
        f"/api/v1/ai/scans/{current_scan_id}/executive-summary",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ai_summary.status_code == 200
    assert ai_summary.json()["scan_id"] == current_scan_id

    first_vuln = client.get("/api/v1/vulnerabilities", headers={"Authorization": f"Bearer {token}"}).json()[0]
    ai_finding = client.get(
        f"/api/v1/ai/findings/{first_vuln['id']}/insight",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ai_finding.status_code == 200
    assert "provenance" in ai_finding.json()



def test_kpi_summary_and_audit_scaffolding(client: TestClient, db_session: Session) -> None:
    token = authenticate_analyst(client)
    run = client.post(
        "/api/v1/scanning/run",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target": "https://api.local",
            "payload": "' OR 1=1 -- <script>alert(1)</script> password='secret'",
            "profile": "deep",
        },
    )
    assert run.status_code == 200

    kpi = client.get("/api/v1/scanning/kpi/summary", headers={"Authorization": f"Bearer {token}"})
    assert kpi.status_code == 200

    audit_actions = [entry.action for entry in db_session.query(AuditLog).all()]
    assert "scan_queued" in audit_actions
    assert "scan_started" in audit_actions
    assert "scan_completed" in audit_actions


def test_devsecops_snippet_scan_and_checklist(client: TestClient) -> None:
    token = authenticate_analyst(client)
    response = client.post(
        "/api/v1/scanning/devsecops/snippet",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target": "repo://service-a",
            "snippet_type": "config",
            "snippet": "allow_privilege_escalation: true\nimage: service:latest\napi_token='secret-token'",
            "profile": "deep",
        },
    )
    assert response.status_code == 200
    scan_id = response.json()["id"]

    checklist = client.get(
        f"/api/v1/scanning/{scan_id}/remediation-checklist",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert checklist.status_code == 200
    assert len(checklist.json()["checklist"]) >= 1

