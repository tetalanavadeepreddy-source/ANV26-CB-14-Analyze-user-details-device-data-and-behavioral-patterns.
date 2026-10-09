from __future__ import annotations

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

LOGGER = logging.getLogger(__name__)
BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
MODEL_DIR = BACKEND_ROOT / "models"
DATASET_PATH = REPO_ROOT / "ml" / "data" / "synthetic_training.csv"
MODEL_VERSION = "fraud_rf_v1"
FEATURE_VERSION = "identity_features_v2"

FEATURE_NAMES = (
    "account_age_hours", "account_age_days", "email_exact_reuse_count", "email_domain_reuse_count",
    "phone_reuse_count", "address_reuse_count", "identity_changes_24h", "verification_verified",
    "device_account_count", "device_age_days", "devices_per_user", "device_change_frequency",
    "ip_account_count", "vpn_indicator", "proxy_indicator", "tor_indicator", "ip_reputation_score",
    "country_change_frequency", "actions_per_minute", "requests_per_second", "failed_login_count",
    "session_duration", "average_action_interval", "action_interval_std", "repeated_action_ratio",
    "navigation_velocity", "login_velocity", "accounts_created_same_hour", "accounts_created_same_day",
    "login_burst_score", "connected_user_count", "shared_device_count", "shared_ip_count", "graph_degree",
    "cluster_size", "cluster_density", "suspicious_neighbor_count",
)

LEGITIMATE_SCENARIOS = (
    "normal_user", "legitimate_shared_wifi", "legitimate_shared_device", "family_shared_device",
    "office_shared_network", "college_shared_network",
)
SUSPICIOUS_SCENARIOS = (
    "device_farm", "identity_farm", "bot_behavior", "rapid_identity_changes", "account_creation_burst",
    "coordinated_accounts", "suspicious_ip_activity", "abnormal_velocity", "synthetic_identity",
)
SCENARIOS = LEGITIMATE_SCENARIOS + SUSPICIOUS_SCENARIOS


def generate_synthetic_dataset(sample_count: int = 6000, seed: int = 42) -> list[dict[str, Any]]:
    if sample_count < 100:
        raise ValueError("sample_count must be at least 100")
    rng = np.random.default_rng(seed)
    rows: list[dict[str, Any]] = []

    for _ in range(sample_count):
        scenario = str(rng.choice(SCENARIOS))
        suspicious = int(scenario in SUSPICIOUS_SCENARIOS)
        age_days = float(np.exp(rng.uniform(np.log(2), np.log(900))))
        row: dict[str, Any] = {
            "scenario": scenario,
            "label": suspicious,
            "account_age_hours": age_days * 24,
            "account_age_days": age_days,
            "email_exact_reuse_count": int(rng.random() < 0.005),
            "email_domain_reuse_count": int(rng.integers(3, 150)),
            "phone_reuse_count": 1,
            "address_reuse_count": 1,
            "identity_changes_24h": int(rng.poisson(0.12)),
            "verification_verified": int(rng.random() < 0.84),
            "device_account_count": int(rng.integers(1, 3)),
            "device_age_days": age_days * float(rng.uniform(0.3, 1.0)),
            "devices_per_user": int(rng.integers(1, 4)),
            "device_change_frequency": float(rng.uniform(0, 0.15)),
            "ip_account_count": int(rng.integers(1, 4)),
            "vpn_indicator": int(rng.random() < 0.04),
            "proxy_indicator": int(rng.random() < 0.02),
            "tor_indicator": int(rng.random() < 0.002),
            "ip_reputation_score": float(rng.uniform(0.55, 1.0)),
            "country_change_frequency": int(rng.integers(1, 3)),
            "actions_per_minute": float(rng.uniform(0.05, 2.5)),
            "requests_per_second": float(rng.uniform(0.002, 0.06)),
            "failed_login_count": int(rng.poisson(0.25)),
            "session_duration": float(rng.uniform(45, 2400)),
            "average_action_interval": float(rng.uniform(8, 180)),
            "action_interval_std": float(rng.uniform(2, 100)),
            "repeated_action_ratio": float(rng.uniform(0.02, 0.3)),
            "navigation_velocity": float(rng.uniform(0.02, 1.4)),
            "login_velocity": float(rng.uniform(0, 2.5)),
            "accounts_created_same_hour": int(rng.integers(1, 3)),
            "accounts_created_same_day": int(rng.integers(1, 6)),
            "login_burst_score": int(rng.integers(0, 3)),
            "connected_user_count": int(rng.integers(0, 3)),
            "shared_device_count": int(rng.integers(0, 2)),
            "shared_ip_count": int(rng.integers(0, 2)),
            "graph_degree": int(rng.integers(0, 4)),
            "cluster_size": int(rng.integers(1, 4)),
            "cluster_density": float(rng.uniform(0, 0.35)),
            "suspicious_neighbor_count": 0,
        }

        if scenario in {"legitimate_shared_wifi", "office_shared_network", "college_shared_network"}:
            row.update({
                "account_age_days": float(rng.uniform(90, 1600)), "account_age_hours": float(rng.uniform(2160, 38400)),
                "verification_verified": int(rng.random() < 0.96), "ip_account_count": int(rng.integers(3, 18)),
                "connected_user_count": int(rng.integers(2, 15)), "shared_ip_count": int(rng.integers(1, 5)),
                "graph_degree": int(rng.integers(1, 7)), "cluster_size": int(rng.integers(3, 18)),
                "cluster_density": float(rng.uniform(0.02, 0.35)), "ip_reputation_score": float(rng.uniform(0.65, 1.0)),
                "suspicious_neighbor_count": 0,
            })
        if scenario in {"legitimate_shared_device", "family_shared_device"}:
            row.update({
                "account_age_days": float(rng.uniform(60, 1400)), "account_age_hours": float(rng.uniform(1440, 33600)),
                "verification_verified": 1, "device_account_count": int(rng.integers(2, 5)),
                "connected_user_count": int(rng.integers(1, 5)), "shared_device_count": int(rng.integers(1, 3)),
                "graph_degree": int(rng.integers(1, 5)), "cluster_size": int(rng.integers(2, 6)),
                "device_age_days": float(rng.uniform(30, 800)), "suspicious_neighbor_count": 0,
            })
        if scenario == "device_farm":
            row.update({
                "device_account_count": int(rng.integers(6, 24)), "device_age_days": float(rng.uniform(0.1, 12)),
                "accounts_created_same_hour": int(rng.integers(4, 24)), "accounts_created_same_day": int(rng.integers(8, 60)),
                "connected_user_count": int(rng.integers(5, 25)), "shared_device_count": int(rng.integers(2, 8)),
                "shared_ip_count": int(rng.integers(1, 5)), "graph_degree": int(rng.integers(5, 22)),
                "cluster_size": int(rng.integers(6, 26)), "cluster_density": float(rng.uniform(0.35, 1)),
                "suspicious_neighbor_count": int(rng.integers(2, 12)), "verification_verified": 0,
            })
        if scenario == "identity_farm":
            row.update({
                "phone_reuse_count": int(rng.integers(3, 13)), "address_reuse_count": int(rng.integers(3, 13)),
                "identity_changes_24h": int(rng.integers(1, 7)), "accounts_created_same_hour": int(rng.integers(3, 18)),
                "connected_user_count": int(rng.integers(3, 15)), "cluster_size": int(rng.integers(4, 16)),
                "suspicious_neighbor_count": int(rng.integers(1, 10)), "verification_verified": 0,
            })
        if scenario == "bot_behavior":
            row.update({
                "actions_per_minute": float(rng.uniform(7, 45)), "requests_per_second": float(rng.uniform(0.15, 1.8)),
                "average_action_interval": float(rng.uniform(0.08, 2.8)), "action_interval_std": float(rng.uniform(0.01, 1.3)),
                "repeated_action_ratio": float(rng.uniform(0.48, 0.98)), "navigation_velocity": float(rng.uniform(4, 30)),
                "login_velocity": float(rng.uniform(4, 25)), "login_burst_score": int(rng.integers(5, 30)),
            })
        if scenario == "rapid_identity_changes":
            row.update({
                "identity_changes_24h": int(rng.integers(3, 13)), "phone_reuse_count": int(rng.integers(1, 5)),
                "address_reuse_count": int(rng.integers(1, 5)), "device_change_frequency": float(rng.uniform(0.4, 2.5)),
                "verification_verified": int(rng.random() < 0.15),
            })
        if scenario == "account_creation_burst":
            row.update({
                "account_age_days": float(rng.uniform(0.01, 8)), "account_age_hours": float(rng.uniform(0.25, 192)),
                "accounts_created_same_hour": int(rng.integers(6, 35)), "accounts_created_same_day": int(rng.integers(10, 90)),
                "verification_verified": int(rng.random() < 0.1), "connected_user_count": int(rng.integers(2, 12)),
            })
        if scenario == "coordinated_accounts":
            row.update({
                "account_age_days": float(rng.uniform(0.1, 18)), "account_age_hours": float(rng.uniform(2, 432)),
                "device_account_count": int(rng.integers(4, 16)), "ip_account_count": int(rng.integers(4, 22)),
                "phone_reuse_count": int(rng.integers(2, 8)), "address_reuse_count": int(rng.integers(2, 8)),
                "identity_changes_24h": int(rng.integers(1, 7)), "accounts_created_same_hour": int(rng.integers(5, 28)),
                "accounts_created_same_day": int(rng.integers(10, 80)), "connected_user_count": int(rng.integers(5, 25)),
                "shared_device_count": int(rng.integers(1, 7)), "shared_ip_count": int(rng.integers(1, 7)),
                "graph_degree": int(rng.integers(5, 24)), "cluster_size": int(rng.integers(6, 28)),
                "cluster_density": float(rng.uniform(0.35, 1)), "suspicious_neighbor_count": int(rng.integers(3, 15)),
                "verification_verified": 0,
            })
        if scenario == "suspicious_ip_activity":
            row.update({
                "ip_account_count": int(rng.integers(3, 18)), "vpn_indicator": int(rng.random() < 0.7),
                "proxy_indicator": int(rng.random() < 0.55), "tor_indicator": int(rng.random() < 0.18),
                "ip_reputation_score": float(rng.uniform(0, 0.38)), "country_change_frequency": int(rng.integers(2, 9)),
                "shared_ip_count": int(rng.integers(1, 7)), "connected_user_count": int(rng.integers(2, 15)),
            })
        if scenario == "abnormal_velocity":
            row.update({
                "actions_per_minute": float(rng.uniform(5, 25)), "requests_per_second": float(rng.uniform(0.08, 1.2)),
                "average_action_interval": float(rng.uniform(0.3, 8)), "action_interval_std": float(rng.uniform(0.1, 5)),
                "repeated_action_ratio": float(rng.uniform(0.25, 0.8)), "navigation_velocity": float(rng.uniform(2, 18)),
                "login_velocity": float(rng.uniform(3, 18)), "login_burst_score": int(rng.integers(4, 20)),
            })
        if scenario == "synthetic_identity":
            row.update({
                "account_age_days": float(rng.uniform(0.1, 25)), "account_age_hours": float(rng.uniform(2, 600)),
                "email_exact_reuse_count": int(rng.random() < 0.08), "phone_reuse_count": int(rng.integers(2, 9)),
                "address_reuse_count": int(rng.integers(2, 9)), "verification_verified": int(rng.random() < 0.12),
                "ip_reputation_score": float(rng.uniform(0.1, 0.65)),
            })

        # Add partial evidence in both classes to model benign anomalies and quiet attacks.
        if rng.random() < 0.18:
            evidence_group = str(rng.choice(("identity", "device", "network", "behavior", "temporal", "graph")))
            if evidence_group == "identity":
                row.update({"phone_reuse_count": 1, "address_reuse_count": 1, "identity_changes_24h": 0})
            elif evidence_group == "device":
                row.update({"device_account_count": int(rng.integers(1, 3)), "shared_device_count": 0})
            elif evidence_group == "network":
                row.update({"ip_account_count": int(rng.integers(1, 3)), "vpn_indicator": 0, "proxy_indicator": 0, "tor_indicator": 0})
            elif evidence_group == "behavior":
                row.update({
                    "actions_per_minute": float(rng.uniform(0.3, 3.5)), "requests_per_second": float(rng.uniform(0.002, 0.08)),
                    "average_action_interval": float(rng.uniform(5, 120)), "repeated_action_ratio": float(rng.uniform(0.02, 0.35)),
                })
            elif evidence_group == "temporal":
                row.update({"accounts_created_same_hour": int(rng.integers(1, 4)), "accounts_created_same_day": int(rng.integers(1, 7))})
            else:
                row.update({
                    "connected_user_count": int(rng.integers(0, 3)), "shared_device_count": 0,
                    "shared_ip_count": 0, "graph_degree": int(rng.integers(0, 3)),
                    "cluster_size": int(rng.integers(1, 4)), "cluster_density": float(rng.uniform(0, 0.3)),
                    "suspicious_neighbor_count": 0,
                })
        if not suspicious and rng.random() < 0.16:
            benign_anomaly = str(rng.choice(("identity", "device", "network", "behavior", "temporal", "graph")))
            if benign_anomaly == "identity":
                row["identity_changes_24h"] = int(rng.integers(1, 4))
            elif benign_anomaly == "device":
                row["device_account_count"] = int(rng.integers(2, 6))
            elif benign_anomaly == "network":
                row["ip_account_count"] = int(rng.integers(3, 12))
            elif benign_anomaly == "behavior":
                row["actions_per_minute"] = float(rng.uniform(2.5, 8))
            elif benign_anomaly == "temporal":
                row["accounts_created_same_hour"] = int(rng.integers(3, 8))
            else:
                row["connected_user_count"] = int(rng.integers(3, 10))

        if rng.random() < 0.1:
            row["verification_verified"] = 1 - int(row["verification_verified"])
        if rng.random() < 0.08:
            row["account_age_days"] = float(rng.uniform(2, 180))
            row["account_age_hours"] = row["account_age_days"] * 24
        if rng.random() < 0.05:
            row["label"] = 1 - int(row["label"])

        for feature in FEATURE_NAMES:
            if isinstance(row[feature], (int, float)):
                row[feature] = float(row[feature])
        rows.append(row)
    return rows


def _dataset_arrays(rows: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray]:
    matrix = np.asarray([[float(row[name]) for name in FEATURE_NAMES] for row in rows], dtype=float)
    labels = np.asarray([int(row["label"]) for row in rows], dtype=int)
    if matrix.shape[1] != len(FEATURE_NAMES) or not np.isfinite(matrix).all():
        raise ValueError("Synthetic feature validation failed")
    if set(np.unique(labels)) != {0, 1}:
        raise ValueError("Training dataset must contain both legitimate (0) and suspicious (1) labels")
    return matrix, labels


def _feedback_arrays(rows: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray]:
    if not rows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=float), np.empty((0,), dtype=int)
    matrix = np.asarray([[float(row[name]) for name in FEATURE_NAMES] for row in rows], dtype=float)
    labels = np.asarray([int(row["label"]) for row in rows], dtype=int)
    if not np.isfinite(matrix).all() or not set(np.unique(labels)).issubset({0, 1}):
        raise ValueError("Investigator feedback feature/label validation failed")
    return matrix, labels


def train_models(
    sample_count: int = 6000,
    seed: int = 42,
    feedback_path: str | Path | None = None,
) -> dict[str, Any]:
    synthetic_rows = generate_synthetic_dataset(sample_count, seed)
    feedback_rows: list[dict[str, Any]] = []
    if feedback_path:
        with Path(feedback_path).open(newline="", encoding="utf-8") as feedback_file:
            for feedback_row in csv.DictReader(feedback_file):
                label = int(feedback_row["actual_label"])
                if label not in {0, 1}:
                    raise ValueError("Feedback actual_label must be 0 or 1")
                feedback_rows.append({
                    "scenario": "investigator_feedback",
                    "label": label,
                    **{name: float(feedback_row[name]) for name in FEATURE_NAMES},
                })
    rows = [*synthetic_rows, *feedback_rows]
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DATASET_PATH.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=["scenario", "label", *FEATURE_NAMES])
        writer.writeheader()
        writer.writerows(rows)

    matrix, labels = _dataset_arrays(synthetic_rows)
    train_x, test_x, train_y, test_y = train_test_split(
        matrix, labels, test_size=0.25, random_state=seed, stratify=labels,
    )
    feedback_x, feedback_y = _feedback_arrays(feedback_rows)
    fit_x = np.vstack((train_x, feedback_x))
    fit_y = np.concatenate((train_y, feedback_y))
    classifier = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("model", RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, max_features="sqrt", class_weight="balanced",
            random_state=seed, n_jobs=-1,
        )),
    ])
    classifier.fit(fit_x, fit_y)
    probabilities = classifier.predict_proba(test_x)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    metrics = {
        "model": "RandomForestClassifier",
        "model_version": MODEL_VERSION,
        "feature_version": FEATURE_VERSION,
        "dataset": "synthetic/generated scenarios with optional investigator labels; not representative of production fraud prevalence",
        "dataset_version": "synthetic_scenarios_v1",
        "dataset_size": len(rows),
        "synthetic_dataset_size": len(synthetic_rows),
        "investigator_feedback_size": len(feedback_rows),
        "train_size": len(fit_y),
        "test_size": len(test_y),
        "seed": seed,
        "accuracy": round(float(accuracy_score(test_y, predictions)), 4),
        "precision": round(float(precision_score(test_y, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(test_y, predictions, zero_division=0)), 4),
        "f1": round(float(f1_score(test_y, predictions, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(test_y, probabilities)), 4),
        "confusion_matrix": confusion_matrix(test_y, predictions, labels=[0, 1]).tolist(),
    }

    normal_train = fit_x[fit_y == 0]
    anomaly_model = IsolationForest(n_estimators=250, contamination="auto", random_state=seed, n_jobs=-1)
    anomaly_model.fit(normal_train)
    normal_scores = anomaly_model.decision_function(normal_train)
    anomaly_bounds = {
        "normal_q05": float(np.quantile(normal_scores, 0.05)),
        "normal_q001": float(np.quantile(normal_scores, 0.001)),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    trained_at = datetime.now().astimezone().isoformat()
    joblib.dump({
        "model": classifier, "feature_names": FEATURE_NAMES, "model_version": MODEL_VERSION,
        "feature_version": FEATURE_VERSION, "trained_at": trained_at,
    }, MODEL_DIR / "fraud_model.joblib")
    joblib.dump({
        "model": anomaly_model, "feature_names": FEATURE_NAMES, "model_version": MODEL_VERSION,
        "feature_version": FEATURE_VERSION, **anomaly_bounds,
    }, MODEL_DIR / "anomaly_model.joblib")
    metrics["anomaly_model"] = "IsolationForest fitted only on legitimate training rows"
    metrics["explanation_method"] = "transparent feature/rule contribution; SHAP not used"
    metrics["trained_at"] = trained_at
    (MODEL_DIR / "evaluation_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    LOGGER.info("Trained %s using %d synthetic rows; test F1=%.3f", MODEL_VERSION, len(rows), metrics["f1"])
    return metrics


class RiskModels:
    def __init__(self, fraud_bundle: dict[str, Any], anomaly_bundle: dict[str, Any], metrics: dict[str, Any]):
        if tuple(fraud_bundle.get("feature_names", ())) != FEATURE_NAMES:
            raise ValueError("Fraud model feature schema does not match the running feature engine")
        if tuple(anomaly_bundle.get("feature_names", ())) != FEATURE_NAMES:
            raise ValueError("Anomaly model feature schema does not match the running feature engine")
        self.fraud_bundle = fraud_bundle
        self.anomaly_bundle = anomaly_bundle
        self.metrics = metrics

    @classmethod
    def load(cls) -> RiskModels | None:
        fraud_path = MODEL_DIR / "fraud_model.joblib"
        anomaly_path = MODEL_DIR / "anomaly_model.joblib"
        metrics_path = MODEL_DIR / "evaluation_metrics.json"
        if not fraud_path.exists() or not anomaly_path.exists() or not metrics_path.exists():
            LOGGER.warning("Trained risk models are missing; run python scripts/train_models.py")
            return None
        return cls(
            joblib.load(fraud_path), joblib.load(anomaly_path),
            json.loads(metrics_path.read_text(encoding="utf-8")),
        )

    def predict(self, features: dict[str, Any]) -> dict[str, float]:
        vector = np.asarray([[float(features.get(name, 0) or 0) for name in FEATURE_NAMES]], dtype=float)
        if not np.isfinite(vector).all():
            raise ValueError("Feature vector contains a non-numeric or non-finite value")
        ml_probability = float(self.fraud_bundle["model"].predict_proba(vector)[0, 1])
        anomaly_raw = float(self.anomaly_bundle["model"].decision_function(vector)[0])
        normal_q05 = self.anomaly_bundle["normal_q05"]
        normal_q001 = self.anomaly_bundle["normal_q001"]
        anomaly_score = 100.0 * min(1.0, max(0.0, (normal_q05 - anomaly_raw) / max(normal_q05 - normal_q001, 1e-9)))
        return {"ml_score": round(ml_probability * 100, 2), "anomaly_score": round(anomaly_score, 2)}

    def feature_importance(self) -> list[dict[str, Any]]:
        forest = self.fraud_bundle["model"].named_steps["model"]
        return sorted(
            ({"feature": name, "importance": round(float(value), 5)} for name, value in zip(FEATURE_NAMES, forest.feature_importances_)),
            key=lambda item: item["importance"], reverse=True,
        )