from fastapi.testclient import TestClient


def create_user_and_token(client: TestClient, email: str, role: str) -> dict[str, str]:
    register_response = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "StrongPassw0rd!", "role": role},
    )
    assert register_response.status_code == 200

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "StrongPassw0rd!"},
    )
    assert login_response.status_code == 200
    return login_response.json()


def test_register_login_refresh_and_me(client: TestClient) -> None:
    token_pair = create_user_and_token(client, "admin@example.com", "admin")

    me_response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_pair['access_token']}"})
    assert me_response.status_code == 200
    assert me_response.json()["email"] == "admin@example.com"

    refresh_response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": token_pair["refresh_token"]},
    )
    assert refresh_response.status_code == 200
    assert refresh_response.json()["access_token"]
    assert refresh_response.json()["refresh_token"] != token_pair["refresh_token"]


def test_password_policy_and_lockout(client: TestClient) -> None:
    weak_register = client.post(
        "/api/v1/auth/register",
        json={"email": "weak@example.com", "password": "weakpassword123!", "role": "viewer"},
    )
    assert weak_register.status_code == 400

    create_user_and_token(client, "locked@example.com", "viewer")
    for _ in range(5):
        failed_login = client.post(
            "/api/v1/auth/login",
            json={"email": "locked@example.com", "password": "WrongPassword1!"},
        )
        assert failed_login.status_code == 401

    locked_login = client.post(
        "/api/v1/auth/login",
        json={"email": "locked@example.com", "password": "StrongPassw0rd!"},
    )
    assert locked_login.status_code == 423


def test_rbac_blocks_viewer_from_scan_and_allows_security_roles(client: TestClient) -> None:
    viewer_tokens = create_user_and_token(client, "viewer@example.com", "viewer")
    scan_response = client.post(
        "/api/v1/scanning/run",
        headers={"Authorization": f"Bearer {viewer_tokens['access_token']}"},
        json={"target": "https://target.local", "payload": "normal payload"},
    )
    assert scan_response.status_code == 403

    analyst_tokens = create_user_and_token(client, "sec-analyst@example.com", "security_analyst")
    analyst_scan = client.post(
        "/api/v1/scanning/run",
        headers={"Authorization": f"Bearer {analyst_tokens['access_token']}"},
        json={"target": "https://target.local", "payload": "' OR 1=1 --"},
    )
    assert analyst_scan.status_code == 200

    developer_tokens = create_user_and_token(client, "dev@example.com", "developer")
    developer_scan = client.post(
        "/api/v1/scanning/run",
        headers={"Authorization": f"Bearer {developer_tokens['access_token']}"},
        json={"target": "https://target.local", "payload": "' OR 1=1 --"},
    )
    assert developer_scan.status_code == 403
