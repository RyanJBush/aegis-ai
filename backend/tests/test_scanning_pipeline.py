from fastapi.testclient import TestClient

from app.models.audit_log import AuditLog


def authenticate_analyst(client: TestClient) -> str:
    client.post(
        "/api/v1/auth/register",
        json={"email": "analyst@example.com", "password": "StrongPassw0rd!", "role": "analyst"},
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

    report_response = client.get(
        "/api/v1/vulnerabilities/reports/summary",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert report_response.status_code == 200
    body = report_response.json()
    assert body["by_rule"]["SQLI"] >= 1
    assert body["by_rule"]["XSS"] >= 1
    assert body["by_owasp"]["A03:2021-Injection"] >= 2


def test_scan_profile_and_workflow_updates(client: TestClient) -> None:
    token = authenticate_analyst(client)
    scan_response = client.post(
        "/api/v1/scanning/run",
        headers={"Authorization": f"Bearer {token}"},
        json={"target": "https://svc.local", "payload": "debug=true md5(password)", "profile": "standard"},
    )
    assert scan_response.status_code == 200
    scan_id = scan_response.json()["id"]
    assert scan_response.json()["status"] == "completed"
    assert scan_response.json()["duration_ms"] is not None

    findings_response = client.get("/api/v1/vulnerabilities", headers={"Authorization": f"Bearer {token}"})
    assert findings_response.status_code == 200
    findings = findings_response.json()
    assert any(v["rule_key"] == "INSECURE_AUTH" for v in findings)
    vuln_id = findings[0]["id"]

    workflow_response = client.patch(
        f"/api/v1/vulnerabilities/{vuln_id}/workflow",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "triaged", "assigned_owner": "dev-team@app.local", "notes": "Investigating fix"},
    )
    assert workflow_response.status_code == 200
    assert workflow_response.json()["status"] == "triaged"
    assert workflow_response.json()["assigned_owner"] == "dev-team@app.local"

    review_response = client.patch(
        f"/api/v1/scanning/{scan_id}/status",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "reviewed"},
    )
    assert review_response.status_code == 200
    assert review_response.json()["status"] == "reviewed"


def test_kpi_summary_and_audit_scaffolding(client: TestClient, db_session) -> None:
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
    kpi_body = kpi.json()
    assert kpi_body["total_findings"] >= 2
    assert kpi_body["high_severity_findings"] >= 1
    assert "scan_coverage_percent" in kpi_body

    audit_actions = [entry.action for entry in db_session.query(AuditLog).all()]
    assert "scan_queued" in audit_actions
    assert "scan_started" in audit_actions
    assert "scan_completed" in audit_actions
