from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.crud import sync_observation
from app.features.feature_engineering import build_user_feature_vector
from app.ml_pipeline import MODEL_VERSION, RiskModels
from app.models import RiskAssessment, RiskIndicator, RiskPrediction, User
from app.risk_scoring import calculate_risk

LOGGER = logging.getLogger(__name__)


def analyze_user_risk(
    db: Session,
    user: User,
    models: RiskModels | None,
    session_id: str | None = None,
    require_models: bool = False,
) -> dict[str, Any]:
    features = build_user_feature_vector(user.id, db)
    if models is None and require_models:
        raise RuntimeError("Trained risk models are not available. Run python scripts/train_models.py and restart the backend.")
    model_scores = models.predict(features) if models else {"ml_score": 0.0, "anomaly_score": 0.0}
    result = calculate_risk(features, model_scores["ml_score"], model_scores["anomaly_score"])
    signals = result["signals"]
    rule_score = round(sum(signals[key] for key in ("identity", "device", "network", "behavior", "temporal")) / 5, 2)
    evidence_coverage = min(
        100,
        12 + min(features["behavior_event_count"], 24) * 1.5
        + min(features["device_link_count"] + features["ip_link_count"], 6) * 7
        + min(features["identity_change_count"], 6) * 3,
    )
    model_version = models.fraud_bundle.get("model_version", MODEL_VERSION) if models else "models_unavailable"

    assessment = RiskAssessment(
        user_id=user.id,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        model_score=model_scores["ml_score"],
        rule_score=rule_score,
        graph_score=signals["graph"],
        behavior_score=signals["behavior"],
        anomaly_score=model_scores["anomaly_score"],
    )
    db.add(assessment)
    db.flush()

    legacy_indicators = _legacy_indicators(features)
    all_reasons = [*result["top_reasons"]]
    known_types = {item["indicator_type"] for item in legacy_indicators}
    for reason in all_reasons:
        indicator_type = reason["feature"]
        if indicator_type in known_types:
            continue
        legacy_indicators.append({
            "indicator_type": indicator_type,
            "severity": "HIGH" if reason["weighted_points"] >= 6 else "MEDIUM" if reason["weighted_points"] >= 2 else "LOW",
            "description": reason["description"],
            "feature_value": str(reason["feature_value"]),
        })
        known_types.add(indicator_type)
    for indicator in legacy_indicators:
        db.add(RiskIndicator(risk_assessment_id=assessment.id, **indicator))

    prediction = RiskPrediction(
        user_id=user.id,
        session_id=session_id,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        decision=result["decision"],
        confidence=result["confidence"],
        ml_score=model_scores["ml_score"],
        anomaly_score=model_scores["anomaly_score"],
        model_version=model_version,
        features=json.dumps(features, allow_nan=False),
        top_reasons=json.dumps({"reasons": result["top_reasons"], "mitigating": result["mitigating_reasons"]}, allow_nan=False),
    )
    db.add(prediction)
    user.risk_score = result["risk_score"]
    user.risk_level = result["risk_level"]
    sync_observation(db, user, result["risk_score"], result["risk_level"], [item["description"] for item in all_reasons])
    db.commit()
    db.refresh(assessment)
    db.refresh(prediction)
    LOGGER.info(
        "Risk prediction id=%d user_id=%d level=%s score=%.2f model=%s",
        prediction.id, user.id, result["risk_level"], result["risk_score"], model_version,
    )
    return {
        "user_id": user.id,
        "session_id": session_id,
        "assessment_id": assessment.id,
        "prediction_id": prediction.id,
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "decision": result["decision"],
        "confidence": result["confidence"],
        "evidence_coverage": evidence_coverage,
        "ml_score": model_scores["ml_score"],
        "ml_probability": round(model_scores["ml_score"] / 100, 4),
        "model_score": model_scores["ml_score"],
        "model_status": "loaded" if models else "missing",
        "model_version": model_version,
        "anomaly_score": model_scores["anomaly_score"],
        "rule_score": rule_score,
        "graph_score": signals["graph"],
        "behavior_score": signals["behavior"],
        "signal_scores": signals,
        "weights": result["weights"],
        "top_reasons": result["top_reasons"],
        "mitigating_reasons": result["mitigating_reasons"],
        "explanation_method": result["explanation_method"],
        "features": features,
        "indicators": legacy_indicators,
    }


def _legacy_indicators(features: dict[str, Any]) -> list[dict[str, str]]:
    indicators: list[dict[str, str]] = []
    device_accounts = int(features["device_account_count"])
    ip_accounts = int(features["ip_account_count"])
    recent_changes = int(features["identity_changes_last_24h"])
    benign_shared_network = (
        features["account_age_days"] >= 30 and features["verification_status"] == "verified"
        and features["ip_reputation"] >= 0.5 and features["actions_per_minute"] < 5 and recent_changes == 0
    )
    if device_accounts > 1:
        benign_shared_device = (
            features["account_age_days"] >= 30 and features["verification_status"] == "verified"
            and features["actions_per_minute"] < 5 and recent_changes == 0
        )
        indicators.append({
            "indicator_type": "device_reuse",
            "severity": "LOW" if benign_shared_device else "HIGH" if device_accounts >= 5 else "MEDIUM",
            "description": (
                f"{device_accounts} established verified accounts share a device; activity is consistent with legitimate use."
                if benign_shared_device else f"A linked device is associated with {device_accounts} identities."
            ),
            "feature_value": str(device_accounts),
        })
    if recent_changes >= 2:
        indicators.append({
            "indicator_type": "rapid_identity_changes",
            "severity": "HIGH" if recent_changes >= 4 else "MEDIUM",
            "description": f"{recent_changes} identity changes were recorded in the last 24 hours.",
            "feature_value": str(recent_changes),
        })
    if ip_accounts > 1:
        indicators.append({
            "indicator_type": "shared_network",
            "severity": "LOW" if benign_shared_network else "HIGH" if ip_accounts >= 8 else "MEDIUM",
            "description": (
                f"{ip_accounts} identities use a shared network; age, verification, and activity are consistent with legitimate shared Wi-Fi."
                if benign_shared_network else f"A linked network is associated with {ip_accounts} identities."
            ),
            "feature_value": str(ip_accounts),
        })
    if features["failed_login_count"] > 0:
        indicators.append({
            "indicator_type": "failed_logins",
            "severity": "HIGH" if features["failed_login_count"] >= 5 else "MEDIUM",
            "description": f"{features['failed_login_count']} failed login events were observed.",
            "feature_value": str(features["failed_login_count"]),
        })
    if features["actions_per_minute"] >= 5:
        indicators.append({
            "indicator_type": "high_request_velocity",
            "severity": "HIGH",
            "description": f"Observed activity reached {features['actions_per_minute']} actions per minute.",
            "feature_value": str(features["actions_per_minute"]),
        })
    for flag, label in (("vpn_flag", "VPN"), ("proxy_flag", "proxy"), ("tor_flag", "Tor")):
        if features[flag]:
            indicators.append({
                "indicator_type": f"network_{label.lower()}",
                "severity": "MEDIUM",
                "description": f"A linked network is marked as using {label} infrastructure.",
                "feature_value": "true",
            })
    return indicators