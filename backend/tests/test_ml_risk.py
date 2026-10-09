import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base, get_db
from app.main import app
from app.ml_pipeline import FEATURE_NAMES
from app.models import Device, InvestigatorFeedback, IPAddress, RiskPrediction, User
from app.main import user_graph
from app.risk_scoring import calculate_risk


def authenticated_user(client, username="risk_subject"):
    registration = client.post("/auth/register", json={
        "username": username,
        "email": f"{username}@example.com",
        "password": "StrongPass!123",
    })
    assert registration.status_code == 200, registration.text
    client.headers["Authorization"] = f"Bearer {registration.json()['token']}"
    return registration.json()["user"]


def test_model_artifacts_train_predict_and_report_synthetic_metrics(trained_risk_models):
    metrics = trained_risk_models.metrics
    assert metrics["dataset_size"] == 1200
    assert metrics["train_size"] + metrics["test_size"] == metrics["dataset_size"]
    assert metrics["dataset"].startswith("synthetic/")
    assert all(0 <= metrics[key] <= 1 for key in ("accuracy", "precision", "recall", "f1", "roc_auc"))
    prediction = trained_risk_models.predict({feature: 0 for feature in FEATURE_NAMES})
    assert 0 <= prediction["ml_score"] <= 100
    assert 0 <= prediction["anomaly_score"] <= 100


def test_risk_api_persists_prediction_hashed_signals_and_feedback(client):
    account = authenticated_user(client)
    result = client.post("/risk/analyze", json={
        "user_id": account["id"],
        "device_id": "device-fingerprint-not-stored",
        "ip": "198.51.100.41",
        "session_id": "risk-session-01",
        "events": [
            {"event_type": "LOGIN", "duration": 2.5},
            {"event_type": "PAGE_VIEW", "duration": 0.3},
            {"event_type": "SEARCH", "duration": 0.2},
        ],
    })
    assert result.status_code == 200, result.text
    prediction = result.json()
    assert 0 <= prediction["risk_score"] <= 100
    assert prediction["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert prediction["decision"] in {"ALLOW", "MONITOR", "REVIEW", "ESCALATE"}
    assert prediction["model_status"] == "loaded"
    assert prediction["model_version"] == "fraud_rf_v1"
    assert prediction["session_id"] == "risk-session-01"
    assert prediction["evidence_coverage"] != prediction["confidence"] or prediction["confidence"] >= 0
    assert all(isinstance(prediction["features"][name], (int, float, bool)) for name in FEATURE_NAMES)
    persisted_risk = client.get(f"/users/{account['id']}/risk").json()
    assert persisted_risk["assessment"]["model_status"] == "loaded"
    assert persisted_risk["assessment"]["decision"] == prediction["decision"]
    assert persisted_risk["assessment"]["signal_scores"] == prediction["signal_scores"]

    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)
    try:
        assert db.query(RiskPrediction).filter(RiskPrediction.id == prediction["prediction_id"]).count() == 1
        assert db.query(Device).filter(Device.device_fingerprint == "device-fingerprint-not-stored").count() == 0
        assert db.query(IPAddress).filter(IPAddress.ip_hash == "198.51.100.41").count() == 0
    finally:
        db_generator.close()

    feedback = client.post(
        f"/risk/predictions/{prediction['prediction_id']}/feedback",
        json={"action": "CONFIRM_FRAUD", "note": "Confirmed during the test workflow."},
    )
    assert feedback.status_code == 200, feedback.text
    assert feedback.json()["status"] == "Feedback collected"
    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)
    try:
        saved = db.query(InvestigatorFeedback).filter(InvestigatorFeedback.prediction_id == prediction["prediction_id"]).one()
        assert saved.actual_label == 1
        assert saved.features == db.query(RiskPrediction).filter(RiskPrediction.id == prediction["prediction_id"]).one().features
    finally:
        db_generator.close()


def test_risk_api_rejects_invalid_events_and_addresses(client):
    account = authenticated_user(client, "invalid_risk_subject")
    invalid_event = client.post("/risk/analyze", json={
        "user_id": account["id"], "events": [{"event_type": "DROP TABLE users"}],
    })
    invalid_ip = client.post("/risk/analyze", json={"user_id": account["id"], "ip": "not-an-ip"})
    assert invalid_event.status_code == 422
    assert invalid_ip.status_code == 422


def test_synthetic_model_metrics_endpoint(client):
    authenticated_user(client, "metrics_subject")
    response = client.get("/models/metrics")
    assert response.status_code == 200
    assert response.json()["model_status"] == "loaded"
    assert response.json()["metrics"]["dataset_size"] == 1200
    assert response.json()["top_features"]


def test_graph_connects_exact_hashed_identifiers_without_exposing_values():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        first = User(username="graph_first", email="first@example.com", password_hash="x", phone_hash="same-phone-hash", address_hash="same-address-hash")
        second = User(username="graph_second", email="second@example.com", password_hash="x", phone_hash="same-phone-hash", address_hash="same-address-hash")
        db.add_all([first, second])
        db.commit()
        graph = user_graph(first.id, db, first)
        assert any(node["id"] == f"user-{second.id}" for node in graph["nodes"])
        assert any(node["type"] == "address" for node in graph["nodes"])
        assert all("same-phone-hash" not in node["details"] and "same-address-hash" not in node["details"] for node in graph["nodes"])


def test_fusion_decisions_and_benign_shared_network():
    benign = {
        "account_age_days": 300, "verification_verified": 1, "ip_reputation_score": 0.9,
        "ip_account_count": 8, "ip_link_count": 1, "device_account_count": 2,
        "actions_per_minute": 0.8, "identity_changes_24h": 0,
    }
    low = calculate_risk(benign, ml_score=8, anomaly_score=0)
    assert low["risk_level"] == "LOW"
    assert any("consistent with legitimate users" in reason for reason in low["mitigating_reasons"])

    critical_features = {
        "account_age_days": 0.5, "verification_verified": 0, "email_exact_reuse_count": 2,
        "phone_reuse_count": 8, "address_reuse_count": 8, "identity_changes_24h": 10,
        "device_account_count": 18, "ip_account_count": 18, "ip_link_count": 1,
        "vpn_indicator": 1, "proxy_indicator": 1, "tor_indicator": 1, "ip_reputation_score": 0.05,
        "country_change_frequency": 8, "actions_per_minute": 30, "requests_per_second": 1.2,
        "average_action_interval": 0.2, "repeated_action_ratio": 0.95, "failed_login_count": 10,
        "navigation_velocity": 20, "accounts_created_same_hour": 24, "accounts_created_same_day": 80,
        "login_burst_score": 30, "login_velocity": 12, "connected_user_count": 24,
        "shared_device_count": 8, "shared_ip_count": 8, "cluster_density": 0.95,
        "suspicious_neighbor_count": 12, "behavior_event_count": 30,
        "device_link_count": 6, "ip_link_count": 6, "identity_change_count": 10,
    }
    critical = calculate_risk(critical_features, ml_score=98, anomaly_score=95)
    assert critical["risk_level"] == "CRITICAL"
    assert critical["decision"] == "ESCALATE"
    assert critical["risk_score"] >= 80
    assert all(reason["weighted_points"] > 0 for reason in critical["top_reasons"])


@pytest.mark.parametrize(("scenario", "expected_levels"), [
    ("normal-user", {"LOW"}),
    ("shared-wifi", {"LOW", "MEDIUM"}),
    ("device-reuse", {"LOW", "MEDIUM"}),
    ("device-farm", {"HIGH", "CRITICAL"}),
    ("identity-farm", {"HIGH", "CRITICAL"}),
    ("bot-behaviour", {"HIGH", "CRITICAL"}),
    ("rapid-identity-changes", {"HIGH", "CRITICAL"}),
    ("coordinated-accounts", {"CRITICAL"}),
    ("account-creation-burst", {"HIGH", "CRITICAL"}),
])
def test_generated_scenario_is_scored_from_persisted_signals(client, scenario, expected_levels):
    authenticated_user(client, f"scenario_runner_{scenario.replace('-', '_')}")
    generated = client.post(f"/demo/scenarios/{scenario}")
    assert generated.status_code == 201, generated.text
    assert all(level == "LOW" for level in (user["risk_level"] for user in client.get("/users").json() if user["id"] in generated.json()["user_ids"]))

    analyses = [client.post(f"/users/{user_id}/analyze").json() for user_id in generated.json()["user_ids"]]
    levels = {analysis["risk_level"] for analysis in analyses}
    print(
        scenario,
        sorted(levels),
        max(analysis["risk_score"] for analysis in analyses),
        analyses[0]["signal_scores"],
        {key: analyses[0]["features"].get(key) for key in (
            "account_age_days", "identity_changes_24h", "device_account_count", "ip_account_count",
            "actions_per_minute", "average_action_interval", "repeated_action_ratio",
            "accounts_created_same_hour", "phone_reuse_count", "address_reuse_count",
            "connected_user_count", "cluster_density", "suspicious_neighbor_count",
        )},
    )
    assert levels.intersection(expected_levels)
    assert all(analysis["model_status"] == "loaded" for analysis in analyses)
    assert all(analysis["prediction_id"] > 0 for analysis in analyses)
