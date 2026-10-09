def test_register_and_login_user(client):
    payload = {
        "username": "demo_user_01",
        "email": "demo_user_01@example.com",
        "password": "StrongPass!123",
        "phone_hash": "hash_phone_001",
        "address_hash": "hash_addr_001",
    }

    register = client.post("/auth/register", json=payload)
    assert register.status_code == 200, register.text

    response_data = register.json()
    assert response_data["user"]["email"] == payload["email"]
    assert "token" in response_data

    duplicate_register = client.post("/auth/register", json=payload)
    assert duplicate_register.status_code == 400
    assert duplicate_register.json()["detail"] == "User already exists"

    login = client.post(
        "/auth/login",
        json={"email": payload["email"], "password": payload["password"]},
    )
    assert login.status_code == 200, login.text
    assert login.json()["user"]["email"] == payload["email"]


def test_invalid_login_fails(client):
    response = client.post(
        "/auth/login",
        json={"email": "unknown@example.com", "password": "wrongpass"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"
