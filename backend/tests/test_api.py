from app.models import User


def register_and_login(client, username="user1", email="user1@example.com", password="Password123"):
    register = client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    assert register.status_code == 201

    login = client.post("/api/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_auth_me(client):
    headers = register_and_login(client)
    response = client.get("/api/auth/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["username"] == "user1"


def test_create_and_list_app_data(client):
    headers = register_and_login(client)
    create = client.post(
        "/api/app/data",
        headers=headers,
        json={"title": "Record", "content": "safe input"},
    )
    assert create.status_code == 200

    listing = client.get("/api/app/data", headers=headers)
    assert listing.status_code == 200
    assert len(listing.json()) == 1


def test_scan_and_vulnerabilities_with_analyst_role(client, db_session):
    headers = register_and_login(client, username="analyst1", email="analyst1@example.com")
    user = db_session.query(User).filter(User.username == "analyst1").first()
    user.role = "analyst"
    db_session.commit()

    login = client.post("/api/auth/login", json={"username": "analyst1", "password": "Password123"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    scan = client.post(
        "/api/scan",
        headers=headers,
        json={
            "target": "webapp",
            "content": "SELECT * FROM users WHERE id = 1 OR 1=1; <script>alert(1)</script>",
        },
    )
    assert scan.status_code == 201

    scan_id = scan.json()["id"]
    get_scan = client.get(f"/api/scan/{scan_id}", headers=headers)
    assert get_scan.status_code == 200
    assert get_scan.json()["vulnerabilities"]

    vuln_list = client.get("/api/vulnerabilities", headers=headers)
    assert vuln_list.status_code == 200
    vuln_id = vuln_list.json()[0]["id"]

    vuln_detail = client.get(f"/api/vulnerabilities/{vuln_id}", headers=headers)
    assert vuln_detail.status_code == 200


def test_scan_forbidden_for_standard_user(client):
    headers = register_and_login(client, username="basic1", email="basic1@example.com")
    scan = client.post("/api/scan", headers=headers, json={"target": "webapp", "content": "safe"})
    assert scan.status_code == 403
