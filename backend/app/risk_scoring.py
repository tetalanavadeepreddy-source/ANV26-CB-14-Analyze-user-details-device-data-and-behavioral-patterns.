from __future__ import annotations

import os
from typing import Any


def _env_float(name: str, default: float) -> float:
    try:
        return max(0.0, float(os.getenv(name, default)))
    except (TypeError, ValueError):
        return default


RISK_WEIGHTS = {
    "identity": _env_float("RISK_WEIGHT_IDENTITY", 0.20),
    "device": _env_float("RISK_WEIGHT_DEVICE", 0.15),
    "network": _env_float("RISK_WEIGHT_NETWORK", 0.10),
    "behavior": _env_float("RISK_WEIGHT_BEHAVIOR", 0.15),
    "temporal": _env_float("RISK_WEIGHT_TEMPORAL", 0.10),
    "graph": _env_float("RISK_WEIGHT_GRAPH", 0.10),
    "ml": _env_float("RISK_WEIGHT_ML", 0.15),
    "anomaly": _env_float("RISK_WEIGHT_ANOMALY", 0.05),
}
if sum(RISK_WEIGHTS.values()) <= 0:
    raise ValueError("At least one RISK_WEIGHT_* value must be positive")
RISK_WEIGHTS = {name: weight / sum(RISK_WEIGHTS.values()) for name, weight in RISK_WEIGHTS.items()}

RISK_THRESHOLDS = {
    "medium": _env_float("RISK_THRESHOLD_MEDIUM", 30),
    "high": _env_float("RISK_THRESHOLD_HIGH", 60),
    "critical": _env_float("RISK_THRESHOLD_CRITICAL", 80),
}
CORROBORATION_THRESHOLD = _env_float("RISK_CORROBORATION_THRESHOLD", 55)
CORROBORATION_BONUS_PER_SIGNAL = _env_float("RISK_CORROBORATION_BONUS_PER_SIGNAL", 12)
CORROBORATION_BONUS_CAP = _env_float("RISK_CORROBORATION_BONUS_CAP", 30)


def _number(features: dict[str, Any], key: str) -> float:
    try:
        value = float(features.get(key, 0) or 0)
        return value if value == value and abs(value) != float("inf") else 0.0
    except (TypeError, ValueError):
        return 0.0


def _capped_score(
    signal: str,
    factors: list[tuple[str, str, float, Any]],
    explanations: list[dict[str, Any]],
) -> float:
    score = 0.0
    for feature, description, amount, value in factors:
        if amount > 0:
            score += amount
            explanations.append({
                "feature": feature, "signal": signal, "description": description,
                "feature_value": value, "signal_points": round(amount, 2),
                "weighted_points": round(amount * RISK_WEIGHTS[signal], 2),
            })
    return min(100.0, max(0.0, score))


def _factor(feature: str, description: str, amount: float, value: Any) -> tuple[str, str, float, Any]:
    return feature, description, max(0.0, amount), value


def calculate_risk(features: dict[str, Any], ml_score: float, anomaly_score: float) -> dict[str, Any]:
    explanations: list[dict[str, Any]] = []
    exact_email_reuse = max(0.0, _number(features, "email_exact_reuse_count") - 1)
    phone_reuse = max(0.0, _number(features, "phone_reuse_count") - 1)
    address_reuse = max(0.0, _number(features, "address_reuse_count") - 1)
    domain_reuse = max(0.0, _number(features, "email_domain_reuse_count") - 50)
    age_days = _number(features, "account_age_days")
    verified = _number(features, "verification_verified") >= 1
    changes = _number(features, "identity_changes_24h")
    device_users = _number(features, "device_account_count")
    ip_users = _number(features, "ip_account_count")
    actions_per_minute = _number(features, "actions_per_minute")
    repeated_action_ratio = _number(features, "repeated_action_ratio")
    ip_reputation = _number(features, "ip_reputation_score")

    identity_factors = [
        _factor("email_exact_reuse_count", "Exact email reused across identities", exact_email_reuse * 45, features.get("email_exact_reuse_count", 0)),
        _factor("phone_reuse_count", "Phone identifier reused", phone_reuse * 18, features.get("phone_reuse_count", 1)),
        _factor("address_reuse_count", "Address identifier reused", address_reuse * 14, features.get("address_reuse_count", 1)),
        _factor("identity_changes_24h", "Recent identity changes", changes * 18, features.get("identity_changes_24h", 0)),
        _factor("account_age_days", "Recently created, unverified account", 15 if age_days < 30 and not verified else 0, age_days),
        _factor("account_age_days", "Very new account", 8 if age_days < 2 else 0, age_days),
        _factor("email_domain_reuse_count", "High email-domain reuse (domain alone is weak evidence)", min(domain_reuse * 0.08, 4), features.get("email_domain_reuse_count", 0)),
    ]
    identity_score = _capped_score("identity", identity_factors, explanations)

    device_factors = [
        _factor("device_account_count", "Device shared by multiple accounts", max(0, device_users - 1) * 9, device_users),
        _factor("device_age_days", "Recently observed shared device", 10 if _number(features, "device_age_days") < 3 and device_users >= 3 else 0, features.get("device_age_days", 0)),
        _factor("devices_per_user", "Unusually frequent device changes", max(0, _number(features, "devices_per_user") - 3) * 6, features.get("devices_per_user", 0)),
    ]
    if device_users > 1 and age_days >= 30 and verified and actions_per_minute < 5 and changes == 0:
        device_factors.append(_factor("device_account_count", "Mature verified users share a device with ordinary activity", -1, device_users))
    device_score = _capped_score("device", device_factors, explanations)
    if device_users > 1 and age_days >= 30 and verified and actions_per_minute < 5 and changes == 0:
        device_score = max(0.0, device_score - 14)

    network_factors = [
        _factor("ip_account_count", "Shared network has multiple linked identities", max(0, ip_users - 1) * 4, ip_users),
        _factor("vpn_indicator", "Network marked as VPN", _number(features, "vpn_indicator") * 9, features.get("vpn_indicator", 0)),
        _factor("proxy_indicator", "Network marked as proxy", _number(features, "proxy_indicator") * 15, features.get("proxy_indicator", 0)),
        _factor("tor_indicator", "Network marked as Tor", _number(features, "tor_indicator") * 22, features.get("tor_indicator", 0)),
        _factor("ip_reputation_score", "Low test/reputation signal", max(0, 0.55 - ip_reputation) * 55, ip_reputation),
        _factor("country_change_frequency", "Frequent country changes", max(0, _number(features, "country_change_frequency") - 2) * 5, features.get("country_change_frequency", 0)),
    ]
    network_score = _capped_score("network", network_factors, explanations)
    benign_shared_network = ip_users > 1 and age_days >= 30 and verified and ip_reputation >= 0.5 and actions_per_minute < 5 and changes == 0
    if benign_shared_network:
        network_score = max(0.0, network_score - 18)

    behavior_factors = [
        _factor("actions_per_minute", "High action frequency", max(0, actions_per_minute - 2) * 3.5, actions_per_minute),
        _factor("requests_per_second", "High request velocity", _number(features, "requests_per_second") * 55, features.get("requests_per_second", 0)),
        _factor("average_action_interval", "Extremely short action intervals", 12 if 0 < _number(features, "average_action_interval") < 1 else 0, features.get("average_action_interval", 0)),
        _factor("repeated_action_ratio", "Repeated actions dominate the session", max(0, repeated_action_ratio - 0.3) * 35, repeated_action_ratio),
        _factor("failed_login_count", "Repeated failed logins", _number(features, "failed_login_count") * 6, features.get("failed_login_count", 0)),
        _factor("navigation_velocity", "Unusually rapid navigation", max(0, _number(features, "navigation_velocity") - 2) * 3, features.get("navigation_velocity", 0)),
    ]
    behavior_score = _capped_score("behavior", behavior_factors, explanations)

    temporal_factors = [
        _factor("accounts_created_same_hour", "Account-creation burst in the same hour", max(0, _number(features, "accounts_created_same_hour") - 3) * 4, features.get("accounts_created_same_hour", 0)),
        _factor("accounts_created_same_day", "Elevated same-day account creation", max(0, _number(features, "accounts_created_same_day") - 5) * 1.5, features.get("accounts_created_same_day", 0)),
        _factor("identity_changes_24h", "Identity-change velocity", changes * 12, changes),
        _factor("login_burst_score", "Login burst in the last hour", max(0, _number(features, "login_burst_score") - 2) * 2.5, features.get("login_burst_score", 0)),
        _factor("login_velocity", "High login velocity", max(0, _number(features, "login_velocity") - 2) * 3, features.get("login_velocity", 0)),
    ]
    temporal_score = _capped_score("temporal", temporal_factors, explanations)

    graph_factors = [
        _factor("connected_user_count", "Many users connected through shared entities", max(0, _number(features, "connected_user_count") - 2) * 2.5, features.get("connected_user_count", 0)),
        _factor("shared_device_count", "Multiple shared-device relationships", _number(features, "shared_device_count") * 7, features.get("shared_device_count", 0)),
        _factor("shared_ip_count", "Multiple shared-network relationships", _number(features, "shared_ip_count") * 4, features.get("shared_ip_count", 0)),
        _factor("cluster_density", "Dense connected-account cluster", max(0, _number(features, "cluster_density") - 0.25) * 35, features.get("cluster_density", 0)),
        _factor("suspicious_neighbor_count", "Connected to previously high-risk identities", _number(features, "suspicious_neighbor_count") * 8, features.get("suspicious_neighbor_count", 0)),
    ]
    graph_score = _capped_score("graph", graph_factors, explanations)

    signals = {
        "identity": round(identity_score, 2), "device": round(device_score, 2),
        "network": round(network_score, 2), "behavior": round(behavior_score, 2),
        "temporal": round(temporal_score, 2), "graph": round(graph_score, 2),
        "ml": round(min(100.0, max(0.0, ml_score)), 2),
        "anomaly": round(min(100.0, max(0.0, anomaly_score)), 2),
    }
    overrides = features.get("_signal_overrides")
    if isinstance(overrides, dict):
        signals = {
            name: round(min(100.0, max(0.0, float(overrides.get(name, signals[name])))), 2)
            for name in RISK_WEIGHTS
        }
    weighted_score = sum(signals[name] * weight for name, weight in RISK_WEIGHTS.items())
    corroborating_signals = [] if isinstance(overrides, dict) else [
        name for name, value in signals.items() if value >= CORROBORATION_THRESHOLD
    ]
    corroboration_bonus = min(
        CORROBORATION_BONUS_CAP,
        max(0, len(corroborating_signals) - 1) * CORROBORATION_BONUS_PER_SIGNAL,
    )
    final_score = round(min(100.0, weighted_score + corroboration_bonus), 2)
    if corroboration_bonus > 0:
        explanations.append({
            "feature": "signal_corroboration",
            "signal": "fusion",
            "description": f"{len(corroborating_signals)} independent elevated signals corroborate one another.",
            "feature_value": ", ".join(corroborating_signals),
            "signal_points": round(corroboration_bonus, 2),
            "weighted_points": round(corroboration_bonus, 2),
        })
    if final_score >= RISK_THRESHOLDS["critical"]:
        risk_level, decision = "CRITICAL", "ESCALATE"
    elif final_score >= RISK_THRESHOLDS["high"]:
        risk_level, decision = "HIGH", "REVIEW"
    elif final_score >= RISK_THRESHOLDS["medium"]:
        risk_level, decision = "MEDIUM", "MONITOR"
    else:
        risk_level, decision = "LOW", "ALLOW"

    event_count = _number(features, "behavior_event_count")
    link_count = _number(features, "device_link_count") + _number(features, "ip_link_count")
    change_count = _number(features, "identity_change_count")
    confidence = min(100, round(12 + min(event_count, 24) * 1.5 + min(link_count, 6) * 7 + min(change_count, 6) * 3))
    if confidence < 45 and risk_level in {"HIGH", "CRITICAL"}:
        decision = "REVIEW"

    top_reasons = sorted(explanations, key=lambda item: item["signal_points"], reverse=True)[:8]
    mitigating_reasons = []
    if benign_shared_network:
        mitigating_reasons.append("Shared infrastructure detected, but account maturity, verification, and behavior are consistent with legitimate users.")
    if device_users > 1 and age_days >= 30 and verified and actions_per_minute < 5 and changes == 0:
        mitigating_reasons.append("Shared device detected, but established verified accounts show ordinary activity.")

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "decision": decision,
        "confidence": confidence,
        "signals": signals,
        "weights": RISK_WEIGHTS,
        "corroboration_bonus": round(corroboration_bonus, 2),
        "top_reasons": top_reasons,
        "mitigating_reasons": mitigating_reasons,
        "explanation_method": "transparent_feature_contribution",
    }