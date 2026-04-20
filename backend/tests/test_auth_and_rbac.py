from fastapi.testclient import TestClient


def create_user_and_token(client: TestClient, email: str, role: str) -> str:
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
    return login_response.json()["access_token"]


def test_register_login_and_me(client: TestClient) -> None:
    token = create_user_and_token(client, "admin@example.com", "admin")

    me_response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_response.status_code == 200
    assert me_response.json()["email"] == "admin@example.com"


def test_rbac_blocks_viewer_from_scan(client: TestClient) -> None:
    viewer_token = create_user_and_token(client, "viewer@example.com", "viewer")

    scan_response = client.post(
        "/api/v1/scanning/run",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"target": "https://target.local", "payload": "normal payload"},
    )
    assert scan_response.status_code == 403
