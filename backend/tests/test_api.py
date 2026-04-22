from fastapi.testclient import TestClient


def register_and_login(
    client: TestClient,
    email: str = "user1@example.com",
    password: str = "Password123!Aa",
    role: str = "viewer",
) -> dict[str, str]:
    register = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "role": role},
    )
    assert register.status_code == 200

    login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_auth_me(client: TestClient) -> None:
    headers = register_and_login(client)
    response = client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == "user1@example.com"


def test_scan_and_vulnerabilities_with_security_analyst_role(client: TestClient) -> None:
    headers = register_and_login(client, email="analyst1@example.com", role="security_analyst")

    scan = client.post(
        "/api/v1/scanning/run",
        headers=headers,
        json={
            "target": "https://webapp.local",
            "payload": "SELECT * FROM users WHERE id = 1 OR 1=1; <script>alert(1)</script>",
        },
    )
    assert scan.status_code == 200

    vuln_list = client.get("/api/v1/vulnerabilities", headers=headers)
    assert vuln_list.status_code == 200
    vuln_id = vuln_list.json()[0]["id"]

    vuln_detail = client.get(f"/api/v1/vulnerabilities/{vuln_id}", headers=headers)
    assert vuln_detail.status_code == 200


def test_scan_forbidden_for_standard_user(client: TestClient) -> None:
    headers = register_and_login(client, email="basic1@example.com", role="viewer")
    scan = client.post(
        "/api/v1/scanning/run",
        headers=headers,
        json={"target": "https://webapp.local", "payload": "safe"},
    )
    assert scan.status_code == 403
