from app.database import get_db
from app.ml_pipeline import FEATURE_NAMES
from app.main import app
from app.models import User


def authenticated_client(client, username):
    registration = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "StrongPass!123",
        },
    )
    assert registration.status_code == 200, registration.text
    set_role(registration.json()["user"]["id"], "ANALYST")
    client.headers["Authorization"] = f"Bearer {registration.json()['token']}"
    return registration.json()["user"]


def set_role(user_id, role):
    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)
    try:
        user = db.query(User).filter(User.id == user_id).first()
        user.role = role
        db.commit()
    finally:
        db_generator.close()


def feature_vector(**overrides):
    features = {name: 0.0 for name in FEATURE_NAMES}
    features.update({
        "user_id": 1,
        "account_age_days": 1,
        "account_age_hours": 24,
        "identity_change_count": 0,
        "identity_changes_last_24h": 0,
        "device_account_count": 1,
        "device_link_count": 1,
        "ip_link_count": 1,
        "ip_account_count": 1,
        "verification_status": "unverified",
        "verification_verified": 0,
        "ip_reputation": 0.0,
        "ip_reputation_score": 0.5,
        "actions_per_minute": 0.0,
        "failed_login_count": 0,
        "account_creation_burst": 0,
        "behavior_event_count": 0,
        "email_exact_reuse_count": 0,
        "email_domain_reuse_count": 0,
        "phone_reuse_count": 1,
        "address_reuse_count": 1,
        "accounts_created_same_hour": 1,
        "accounts_created_same_day": 1,
        "vpn_flag": False,
        "proxy_flag": False,
        "tor_flag": False,
    })
    features.update(overrides)
    return features


def test_scanner_observation_lifecycle_and_activity(client, monkeypatch):
    user = authenticated_client(client, "observation_subject")
    current_features = feature_vector()
    monkeypatch.setattr("app.risk_service.build_user_feature_vector", lambda user_id, db: current_features)

    low = client.post(f"/users/{user['id']}/analyze")
    assert low.status_code == 200
    assert low.json()["risk_level"] == "LOW"
    assert client.get("/observations").json() == []

    current_features.update({
        "device_account_count": 6,
        "ip_account_count": 8,
        "identity_changes_last_24h": 4,
        "identity_changes_24h": 4,
        "email_exact_reuse_count": 1,
        "phone_reuse_count": 3,
        "accounts_created_same_hour": 8,
        "failed_login_count": 3,
    })
    medium = client.post(f"/users/{user['id']}/analyze")
    assert medium.status_code == 200
    assert medium.json()["risk_level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    observations = client.get("/observations").json()
    assert len(observations) == 1
    observation_id = observations[0]["id"]
    assert observations[0]["status"] == "ACTIVE"
    assert observations[0]["reasons"]

    repeated = client.post(f"/users/{user['id']}/analyze")
    assert repeated.status_code == 200
    assert len(client.get("/observations").json()) == 1

    failed_login = client.post("/auth/login", json={"email": "observation_subject@example.com", "password": "wrong-password"})
    assert failed_login.status_code == 401
    login = client.post("/auth/login", json={"email": "observation_subject@example.com", "password": "StrongPass!123"})
    assert login.status_code == 200
    current_features.update({
        "device_account_count": 5,
        "ip_account_count": 8,
        "identity_changes_last_24h": 4,
        "identity_changes_24h": 4,
        "failed_login_count": 5,
        "actions_per_minute": 5,
        "device_account_count": 10,
        "ip_account_count": 15,
        "phone_reuse_count": 8,
        "address_reuse_count": 8,
        "accounts_created_same_hour": 12,
        "accounts_created_same_day": 20,
        "vpn_flag": True,
        "proxy_flag": True,
        "tor_flag": True,
    })
    event = client.post("/events", json={
        "user_id": user["id"],
        "session_id": "observed-session",
        "event_type": "PROFILE_VIEW",
        "event_metadata": "{}",
    })
    assert event.status_code == 200
    elevated_level = client.get(f"/users/{user['id']}/risk").json()["risk_level"]
    assert elevated_level in {"HIGH", "CRITICAL"}
    logout = client.post("/auth/logout")
    assert logout.status_code == 200
    history = client.get(f"/users/{user['id']}/observation").json()
    assert history["is_observed"] is True
    activity_types = {activity["activity_type"] for activity in history["active_observation"]["activities"]}
    assert {"FAILED_LOGIN", "LOGIN", "PROFILE_VIEW", "LOGOUT"}.issubset(activity_types)

    high = client.post(f"/users/{user['id']}/analyze")
    assert high.status_code == 200
    assert high.json()["risk_level"] in {"HIGH", "CRITICAL"}
    assert len(client.get("/observations").json()) == 1
    assert client.get(f"/observations/{observation_id}").json()["risk_level"] == high.json()["risk_level"]

    current_features.clear()
    current_features.update(feature_vector())
    resolved = client.post(f"/users/{user['id']}/analyze")
    assert resolved.json()["risk_level"] == "LOW"
    assert client.get("/observations").json() == []
    history = client.get(f"/users/{user['id']}/observation").json()
    assert history["is_observed"] is False
    assert history["history"][0]["status"] == "RESOLVED"
    assert history["history"][0]["risk_level"] == high.json()["risk_level"]
    assert history["history"][0]["reasons"]


def test_legacy_assessment_also_enters_observation(client):
    user = authenticated_client(client, "legacy_observation_subject")
    response = client.post("/risk-assessment", json={
        "user_id": user["id"],
        "model_score": 55,
        "rule_score": 55,
        "graph_score": 55,
        "behavior_score": 55,
        "anomaly_score": 55,
    })
    assert response.status_code == 200
    assert response.json()["risk_level"] == "MEDIUM"
    observations = client.get("/observations").json()
    assert len(observations) == 1
    assert observations[0]["user_id"] == user["id"]


def test_regular_user_cannot_claim_staff_role_or_read_observations(client):
    registration = client.post("/auth/register", json={
        "username": "self_promoted_user",
        "email": "self_promoted_user@example.com",
        "password": "StrongPass!123",
        "role": "ADMIN",
    })
    assert registration.status_code == 200
    assert registration.json()["user"]["role"] == "USER"
    client.headers["Authorization"] = f"Bearer {registration.json()['token']}"

    assert client.get("/observations").status_code == 403
    assert client.get("/observations/1").status_code == 403
    assert client.get(f"/users/{registration.json()['user']['id']}/observation").status_code == 403
    assert client.post(f"/users/{registration.json()['user']['id']}/observation").status_code == 403
    assert client.patch("/observations/1", json={"status": "RESOLVED"}).status_code == 403
    assert client.delete("/observations/1").status_code == 403