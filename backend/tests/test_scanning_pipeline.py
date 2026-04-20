from fastapi.testclient import TestClient


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
