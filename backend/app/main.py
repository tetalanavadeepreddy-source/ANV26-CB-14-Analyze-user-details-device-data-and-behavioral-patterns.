import json
import hashlib
import logging
import os
import uuid
from datetime import datetime
from typing import Any

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

load_dotenv()

from app.auth import create_access_token, get_current_user, get_password_hash, require_role, verify_password
from app.crud import create_behavior_event, create_risk_assessment, create_user, get_dashboard_signals, get_dashboard_stats, get_user_by_email, get_user_by_id, list_risk_assessments, record_observation_activity, sync_observation
from app.database import Base, engine, get_db
from app.demo_scenarios import SCENARIOS, generate_demo_scenario
from app.features.feature_engineering import build_user_feature_vector
from app.ml_pipeline import RiskModels
from app.models import BehaviorEvent, Device, IdentityChange, IPAddress, Investigation, InvestigatorFeedback, Observation, ObservationActivity, RiskAssessment, RiskIndicator, RiskPrediction, User, UserDevice, UserIPAddress
from app.risk_scoring import calculate_risk
from app.risk_service import analyze_user_risk
from app.schemas import DashboardStats, EventCreate, InvestigatorFeedbackCreate, ObservationStatusUpdate, RiskAnalyzeRequest, RiskAnalyzeResponse, RiskAssessmentCreate, RiskAssessmentRead, UserCreate, UserLogin, UserRead

Base.metadata.create_all(bind=engine)
observation_staff = require_role("ADMIN", "ANALYST")
logger = logging.getLogger(__name__)
risk_models = RiskModels.load()

app = FastAPI(title="IdentityGuard-X", version="0.1.0")

cors_origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root() -> dict[str, str]:
    return {"app": "IdentityGuard-X", "status": "running"}


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "identityguard-x"}


@app.post("/auth/register")
def register_user(payload: UserCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    existing = db.query(User).filter((User.email == payload.email) | (User.username == payload.username)).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    user = create_user(
        db,
        username=payload.username,
        email=str(payload.email),
        password_hash=get_password_hash(payload.password),
        phone_hash=payload.phone_hash,
        address_hash=payload.address_hash,
        role="USER",
    )
    token = create_access_token(str(user.id))
    return {
        "user": {"id": user.id, "username": user.username, "email": user.email, "role": user.role},
        "token": token,
    }


@app.post("/auth/login")
def login_user(payload: UserLogin, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = get_user_by_email(db, str(payload.email))
    if not user or not verify_password(payload.password, user.password_hash):
        if user:
            record_observation_activity(db, user.id, "FAILED_LOGIN")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    record_observation_activity(db, user.id, "LOGIN")
    token = create_access_token(str(user.id))
    return {"token": token, "user": {"id": user.id, "username": user.username, "email": user.email, "role": user.role}}


@app.post("/auth/logout")
def logout_user(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> dict[str, str]:
    record_observation_activity(db, current_user.id, "LOGOUT")
    return {"status": "ok"}


@app.get("/auth/me", response_model=UserRead)
def get_me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@app.get("/users", response_model=list[UserRead])
def list_users(
    search: str | None = None,
    risk_level: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[User]:
    query = db.query(User)
    if search:
        search_term = search.strip()
        filters = [User.username.ilike(f"%{search_term}%"), User.email.ilike(f"%{search_term}%")]
        if search_term.isdigit():
            filters.append(User.id == int(search_term))
        query = query.filter(or_(*filters))
    if risk_level:
        normalized_risk = risk_level.upper()
        if normalized_risk not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise HTTPException(status_code=422, detail="Risk level must be LOW, MEDIUM, HIGH, or CRITICAL")
        latest_assessments = (
            db.query(func.max(RiskAssessment.id).label("assessment_id"))
            .group_by(RiskAssessment.user_id)
            .subquery()
        )
        query = (
            query.join(RiskAssessment, RiskAssessment.user_id == User.id)
            .join(latest_assessments, RiskAssessment.id == latest_assessments.c.assessment_id)
            .filter(RiskAssessment.risk_level == normalized_risk)
        )
    return query.order_by(User.created_at.desc()).limit(limit).all()


@app.get("/users/{user_id}", response_model=UserRead)
def get_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> User:
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/dashboard/statistics")
def dashboard_statistics(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> DashboardStats:
    stats = get_dashboard_stats(db)
    return DashboardStats(**stats)


@app.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> dict[str, int]:
    latest_assessments = (
        db.query(func.max(RiskAssessment.id).label("assessment_id"))
        .group_by(RiskAssessment.user_id)
        .subquery()
    )
    risk_counts = dict(
        db.query(RiskAssessment.risk_level, func.count(RiskAssessment.user_id))
        .join(latest_assessments, RiskAssessment.id == latest_assessments.c.assessment_id)
        .group_by(RiskAssessment.risk_level)
        .all()
    )
    return {
        "total_users": db.query(User).count(),
        "high_risk": risk_counts.get("HIGH", 0),
        "critical_risk": risk_counts.get("CRITICAL", 0),
        "medium_risk": risk_counts.get("MEDIUM", 0),
        "low_risk": risk_counts.get("LOW", 0),
        "open_investigations": db.query(Investigation).filter(Investigation.status.in_(["open", "under_review", "verification_required"])).count(),
        "analyzed_users": sum(risk_counts.values()),
        **get_dashboard_signals(db),
    }


@app.get("/dashboard/risk-distribution")
def dashboard_risk_distribution(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> list[dict[str, Any]]:
    latest_assessments = (
        db.query(func.max(RiskAssessment.id).label("assessment_id"))
        .group_by(RiskAssessment.user_id)
        .subquery()
    )
    counts = dict(
        db.query(RiskAssessment.risk_level, func.count(RiskAssessment.user_id))
        .join(latest_assessments, RiskAssessment.id == latest_assessments.c.assessment_id)
        .group_by(RiskAssessment.risk_level)
        .all()
    )
    return [{"level": level, "count": counts.get(level, 0)} for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")]


@app.get("/dashboard/recent-alerts")
def dashboard_recent_alerts(
    limit: int = Query(default=8, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict[str, Any]]:
    assessments = (
        db.query(RiskAssessment)
        .order_by(RiskAssessment.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": assessment.id,
            "user_id": assessment.user_id,
            "username": assessment.user.username if assessment.user else "Unknown",
            "email": assessment.user.email if assessment.user else "",
            "risk_score": assessment.risk_score,
            "risk_level": assessment.risk_level,
            "created_at": assessment.created_at,
        }
        for assessment in assessments
    ]


@app.get("/dashboard/top-indicators")
def dashboard_top_indicators(
    limit: int = Query(default=6, ge=1, le=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict[str, Any]]:
    rows = (
        db.query(RiskIndicator.indicator_type, func.count(RiskIndicator.id))
        .join(RiskAssessment, RiskAssessment.id == RiskIndicator.risk_assessment_id)
        .group_by(RiskIndicator.indicator_type)
        .order_by(func.count(RiskIndicator.id).desc())
        .limit(limit)
        .all()
    )
    return [{"indicator_type": indicator_type, "count": count} for indicator_type, count in rows]


def _observation_payload(observation: Observation, db: Session, include_details: bool = False) -> dict[str, Any]:
    user = observation.user
    try:
        reasons = json.loads(observation.reasons or "[]")
    except (TypeError, json.JSONDecodeError):
        reasons = []
    payload: dict[str, Any] = {
        "id": observation.id,
        "user_id": observation.user_id,
        "username": user.username if user else "Unknown",
        "risk_score": observation.risk_score,
        "risk_level": observation.risk_level,
        "reasons": reasons,
        "started_at": observation.started_at,
        "updated_at": observation.updated_at,
        "status": observation.status,
    }
    if include_details:
        activities = (
            db.query(ObservationActivity)
            .filter(ObservationActivity.observation_id == observation.id)
            .order_by(ObservationActivity.timestamp.desc())
            .all()
        )
        payload["activities"] = [
            {"id": activity.id, "activity_type": activity.activity_type, "timestamp": activity.timestamp, "details": activity.details}
            for activity in activities
        ]
        payload["devices"] = [
            {
                "id": link.device.id,
                "device_type": link.device.device_type,
                "operating_system": link.device.operating_system,
                "browser": link.device.browser,
            }
            for link in (user.user_devices if user else [])
        ]
        payload["networks"] = [
            {"country": link.ip_address.country, "region": link.ip_address.region, "isp": link.ip_address.isp}
            for link in (user.user_ips if user else [])
        ]
    return payload


@app.get("/observations")
def list_observations(db: Session = Depends(get_db), current_user: User = Depends(observation_staff)) -> list[dict[str, Any]]:
    observations = (
        db.query(Observation)
        .filter(Observation.status == "ACTIVE")
        .order_by(Observation.started_at.desc())
        .all()
    )
    return [_observation_payload(observation, db) for observation in observations]


@app.get("/observations/{observation_id}")
def get_observation(observation_id: int, db: Session = Depends(get_db), current_user: User = Depends(observation_staff)) -> dict[str, Any]:
    observation = db.query(Observation).filter(Observation.id == observation_id).first()
    if not observation:
        raise HTTPException(status_code=404, detail="Observation not found")
    return _observation_payload(observation, db, include_details=True)


@app.get("/users/{user_id}/observation")
def user_observation_history(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(observation_staff)) -> dict[str, Any]:
    if not get_user_by_id(db, user_id):
        raise HTTPException(status_code=404, detail="User not found")
    history = (
        db.query(Observation)
        .filter(Observation.user_id == user_id)
        .order_by(Observation.started_at.desc())
        .all()
    )
    history_payload = [_observation_payload(observation, db, include_details=True) for observation in history]
    active = next((observation for observation in history_payload if observation["status"] == "ACTIVE"), None)
    return {
        "user_id": user_id,
        "is_observed": active is not None,
        "active_observation": active,
        "history": history_payload,
    }


@app.post("/users/{user_id}/observation")
def add_user_to_observation(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(observation_staff)) -> dict[str, Any]:
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.risk_level not in {"MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(status_code=409, detail="Only MEDIUM, HIGH, or CRITICAL risk accounts can be observed")
    assessment = (
        db.query(RiskAssessment)
        .filter(RiskAssessment.user_id == user_id)
        .order_by(RiskAssessment.id.desc())
        .first()
    )
    reasons = [indicator.description for indicator in assessment.indicators] if assessment else []
    observation = sync_observation(db, user, user.risk_score, user.risk_level, reasons)
    db.commit()
    db.refresh(observation)
    return _observation_payload(observation, db)


@app.patch("/observations/{observation_id}")
def update_observation_status(
    observation_id: int,
    payload: ObservationStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(observation_staff),
) -> dict[str, Any]:
    observation = db.query(Observation).filter(Observation.id == observation_id).first()
    if not observation:
        raise HTTPException(status_code=404, detail="Observation not found")
    if payload.status == "ACTIVE":
        user = get_user_by_id(db, observation.user_id)
        if user.risk_level not in {"MEDIUM", "HIGH", "CRITICAL"}:
            raise HTTPException(status_code=409, detail="Only MEDIUM, HIGH, or CRITICAL risk accounts can be observed")
        if observation.status != "ACTIVE":
            assessment = (
                db.query(RiskAssessment)
                .filter(RiskAssessment.user_id == user.id)
                .order_by(RiskAssessment.id.desc())
                .first()
            )
            reasons = [indicator.description for indicator in assessment.indicators] if assessment else []
            observation = sync_observation(db, user, user.risk_score, user.risk_level, reasons)
    else:
        user = get_user_by_id(db, observation.user_id)
        if user.risk_level != "LOW":
            raise HTTPException(status_code=409, detail="An account must be LOW risk before observation can be resolved")
        observation.status = "RESOLVED"
        observation.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(observation)
    return _observation_payload(observation, db)


@app.delete("/observations/{observation_id}")
def remove_observation(observation_id: int, db: Session = Depends(get_db), current_user: User = Depends(observation_staff)) -> dict[str, Any]:
    observation = db.query(Observation).filter(Observation.id == observation_id).first()
    if not observation:
        raise HTTPException(status_code=404, detail="Observation not found")
    user = get_user_by_id(db, observation.user_id)
    if user.risk_level != "LOW":
        raise HTTPException(status_code=409, detail="An account must be LOW risk before observation can be removed")
    observation.status = "RESOLVED"
    observation.updated_at = datetime.utcnow()
    db.commit()
    return {"id": observation.id, "status": observation.status}


@app.get("/risk-assessments")
def risk_assessments(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return list_risk_assessments(db)


@app.post("/risk-assessment", response_model=RiskAssessmentRead)
def create_assessment(payload: RiskAssessmentCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> Any:
    user = db.query(User).filter(User.id == payload.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    assessment = create_risk_assessment(
        db,
        user_id=payload.user_id,
        model_score=payload.model_score,
        rule_score=payload.rule_score,
        graph_score=payload.graph_score,
        behavior_score=payload.behavior_score,
        anomaly_score=payload.anomaly_score,
    )
    return assessment


@app.post("/events")
def create_event(payload: EventCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    was_observed = db.query(Observation).filter(
        Observation.user_id == payload.user_id,
        Observation.status == "ACTIVE",
    ).first() is not None
    event = create_behavior_event(
        db,
        user_id=payload.user_id,
        session_id=payload.session_id,
        event_type=payload.event_type,
        duration=payload.duration,
        event_metadata=payload.event_metadata or "{}",
    )
    if was_observed:
        record_observation_activity(db, payload.user_id, payload.event_type, payload.event_metadata or "{}")
        observed_user = get_user_by_id(db, payload.user_id)
        if observed_user:
            analyze_user_risk(db, observed_user, risk_models, payload.session_id)
    return {"id": event.id, "user_id": event.user_id, "event_type": event.event_type}


@app.get("/users/{user_id}/risk")
def user_risk(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    assessment = (
        db.query(RiskAssessment)
        .filter(RiskAssessment.user_id == user_id)
        .order_by(RiskAssessment.id.desc())
        .first()
    )
    if not assessment:
        return {"user_id": user.id, "analyzed": False, "risk_score": None, "risk_level": None, "assessment": None}
    event_count = db.query(BehaviorEvent).filter(BehaviorEvent.user_id == user_id).count()
    link_count = (
        db.query(UserDevice).filter(UserDevice.user_id == user_id).count()
        + db.query(UserIPAddress).filter(UserIPAddress.user_id == user_id).count()
    )
    identity_change_count = db.query(IdentityChange).filter(IdentityChange.user_id == user_id).count()
    prediction = (
        db.query(RiskPrediction)
        .filter(RiskPrediction.user_id == user_id)
        .order_by(RiskPrediction.id.desc())
        .first()
    )
    prediction_features = json.loads(prediction.features) if prediction else {}
    prediction_fusion = calculate_risk(prediction_features, prediction.ml_score, prediction.anomaly_score) if prediction else None
    saved_reasons = json.loads(prediction.top_reasons) if prediction else {}
    return {
        "user_id": user.id,
        "analyzed": True,
        "risk_score": assessment.risk_score,
        "risk_level": assessment.risk_level,
        "assessment": {
            "id": assessment.id,
            "created_at": assessment.created_at,
            "evidence_coverage": _evidence_coverage(event_count, link_count, identity_change_count),
            "model_score": assessment.model_score,
            "model_status": "loaded" if prediction and prediction.model_version != "models_unavailable" else "missing",
            "decision": prediction.decision if prediction else None,
            "confidence": prediction.confidence if prediction else None,
            "model_version": prediction.model_version if prediction else None,
            "prediction_id": prediction.id if prediction else None,
            "signal_scores": prediction_fusion["signals"] if prediction_fusion else None,
            "weights": prediction_fusion["weights"] if prediction_fusion else None,
            "top_reasons": saved_reasons.get("reasons", []),
            "mitigating_reasons": saved_reasons.get("mitigating", []),
            "rule_score": assessment.rule_score,
            "graph_score": assessment.graph_score,
            "behavior_score": assessment.behavior_score,
            "anomaly_score": assessment.anomaly_score,
        },
    }


@app.get("/users/{user_id}/events")
def user_events(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from app.models import BehaviorEvent

    events = db.query(BehaviorEvent).filter(BehaviorEvent.user_id == user_id).order_by(BehaviorEvent.timestamp.desc()).all()
    return {"user_id": user_id, "events": events}


@app.get("/users/{user_id}/features")
def user_features(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return build_user_feature_vector(user_id, db)


@app.get("/users/{user_id}/timeline")
def user_timeline(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    events = db.query(BehaviorEvent).filter(BehaviorEvent.user_id == user_id).order_by(BehaviorEvent.timestamp.desc()).all()
    changes = db.query(IdentityChange).filter(IdentityChange.user_id == user_id).order_by(IdentityChange.timestamp.desc()).all()
    return {
        "behavior_events": [
            {
                "id": event.id,
                "user_id": event.user_id,
                "session_id": event.session_id,
                "event_type": event.event_type,
                "timestamp": event.timestamp,
                "duration": event.duration,
                "event_metadata": event.event_metadata,
            }
            for event in events
        ],
        "identity_changes": [
            {
                "id": change.id,
                "user_id": change.user_id,
                "field_changed": change.field_changed,
                "timestamp": change.timestamp,
            }
            for change in changes
        ],
    }


def _bounded_score(value: float) -> float:
    return round(min(100.0, max(0.0, value)), 2)


def _evidence_coverage(event_count: int, link_count: int, identity_change_count: int) -> int:
    return min(100, 35 + min(event_count, 30) + min(link_count * 5, 20) + min(identity_change_count * 3, 15))


def _build_indicators(features: dict[str, Any]) -> list[dict[str, str]]:
    indicators: list[dict[str, str]] = []
    device_accounts = int(features["device_account_count"])
    ip_accounts = int(features["ip_account_count"])
    recent_changes = int(features["identity_changes_last_24h"])
    if device_accounts > 1:
        severity = "HIGH" if device_accounts >= 5 else "MEDIUM"
        indicators.append({
            "indicator_type": "device_reuse",
            "severity": severity,
            "description": f"A linked device is associated with {device_accounts} identities.",
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
        benign_shared_network = (
            features["account_age_days"] >= 30
            and features["verification_status"] == "verified"
            and features["ip_reputation"] >= 0.5
            and features["actions_per_minute"] < 5
            and recent_changes == 0
        )
        indicators.append({
            "indicator_type": "shared_network",
            "severity": "LOW" if benign_shared_network else "HIGH" if ip_accounts >= 8 else "MEDIUM",
            "description": (
                f"{ip_accounts} identities use a shared network; age, verification, and activity are consistent with legitimate shared Wi-Fi."
                if benign_shared_network
                else f"A linked network is associated with {ip_accounts} identities."
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


@app.post("/users/{user_id}/analyze")
def analyze_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return analyze_user_risk(db, user, risk_models)


def _hash_identifier(kind: str, value: str) -> str:
    return hashlib.sha256(f"{kind}:{value}".encode("utf-8")).hexdigest()


@app.post("/risk/analyze", response_model=RiskAnalyzeResponse)
def analyze_risk_request(
    payload: RiskAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    if risk_models is None:
        raise HTTPException(status_code=503, detail="Risk models are unavailable. Train the models and restart the backend.")
    user = get_user_by_id(db, payload.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    session_id = payload.session_id or uuid.uuid4().hex
    now = datetime.utcnow()

    if payload.device_id:
        fingerprint = _hash_identifier("device", payload.device_id)
        device = db.query(Device).filter(Device.device_fingerprint == fingerprint).first()
        if device is None:
            device = Device(device_fingerprint=fingerprint, first_seen=now, last_seen=now)
            db.add(device)
            db.flush()
        link = db.query(UserDevice).filter(UserDevice.user_id == user.id, UserDevice.device_id == device.id).first()
        if link is None:
            db.add(UserDevice(user_id=user.id, device_id=device.id, first_seen=now, last_seen=now, usage_count=1))
        else:
            link.last_seen = now
            link.usage_count += 1

    if payload.ip:
        ip_hash = _hash_identifier("ip", str(payload.ip))
        ip_record = db.query(IPAddress).filter(IPAddress.ip_hash == ip_hash).first()
        if ip_record is None:
            ip_record = IPAddress(ip_hash=ip_hash, reputation_score=0.5, isp="unrated-client-input")
            db.add(ip_record)
            db.flush()
        link = db.query(UserIPAddress).filter(UserIPAddress.user_id == user.id, UserIPAddress.ip_id == ip_record.id).first()
        if link is None:
            db.add(UserIPAddress(user_id=user.id, ip_id=ip_record.id, first_seen=now, last_seen=now, usage_count=1))
        else:
            link.last_seen = now
            link.usage_count += 1

    for event in payload.events:
        db.add(BehaviorEvent(
            user_id=user.id,
            session_id=session_id,
            event_type=event.event_type.upper(),
            timestamp=event.timestamp or now,
            duration=event.duration,
            event_metadata='{"source":"risk_api"}',
        ))
    db.flush()
    return analyze_user_risk(db, user, risk_models, session_id, require_models=True)


@app.get("/models/metrics")
def model_metrics(current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    if risk_models is None:
        return {"model_status": "missing", "metrics": None, "top_features": []}
    return {
        "model_status": "loaded",
        "metrics": risk_models.metrics,
        "top_features": risk_models.feature_importance()[:10],
    }


@app.post("/risk/predictions/{prediction_id}/feedback")
def submit_investigator_feedback(
    prediction_id: int,
    payload: InvestigatorFeedbackCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    prediction = db.query(RiskPrediction).filter(RiskPrediction.id == prediction_id).first()
    if prediction is None:
        raise HTTPException(status_code=404, detail="Prediction not found")
    feedback = InvestigatorFeedback(
        prediction_id=prediction.id,
        user_id=prediction.user_id,
        analyst_id=current_user.id,
        actual_label=1 if payload.action == "CONFIRM_FRAUD" else 0,
        feedback_action=payload.action,
        features=prediction.features,
        note=payload.note,
    )
    db.add(feedback)
    db.commit()
    db.refresh(feedback)
    return {"id": feedback.id, "prediction_id": prediction_id, "status": "Feedback collected", "actual_label": feedback.actual_label}


@app.get("/users/{user_id}/indicators")
def user_indicators(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> list[dict[str, Any]]:
    if not get_user_by_id(db, user_id):
        raise HTTPException(status_code=404, detail="User not found")
    assessment = (
        db.query(RiskAssessment)
        .filter(RiskAssessment.user_id == user_id)
        .order_by(RiskAssessment.created_at.desc())
        .first()
    )
    if not assessment:
        return []
    return [
        {
            "id": indicator.id,
            "indicator_type": indicator.indicator_type,
            "description": indicator.description,
            "severity": indicator.severity,
            "feature_value": indicator.feature_value,
        }
        for indicator in assessment.indicators
    ]


@app.get("/users/{user_id}/graph")
def user_graph(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    device_ids = [link.device_id for link in user.user_devices]
    ip_ids = [link.ip_id for link in user.user_ips]
    related_ids: set[int] = set()
    if device_ids:
        related_ids.update(row[0] for row in db.query(UserDevice.user_id).filter(UserDevice.device_id.in_(device_ids)).all())
    if ip_ids:
        related_ids.update(row[0] for row in db.query(UserIPAddress.user_id).filter(UserIPAddress.ip_id.in_(ip_ids)).all())
    if user.email:
        related_ids.update(row[0] for row in db.query(User.id).filter(func.lower(User.email) == user.email.lower()).all())
    if user.phone_hash:
        related_ids.update(row[0] for row in db.query(User.id).filter(User.phone_hash == user.phone_hash).all())
    if user.address_hash:
        related_ids.update(row[0] for row in db.query(User.id).filter(User.address_hash == user.address_hash).all())
    related_ids.discard(user_id)
    related_ids = set(sorted(related_ids)[:20])
    allowed_user_ids = related_ids | {user_id}
    graph_users = db.query(User).filter(User.id.in_(allowed_user_ids)).all()
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    for graph_user in graph_users:
        user_node_id = f"user-{graph_user.id}"
        nodes[user_node_id] = {
            "id": user_node_id,
            "label": graph_user.username,
            "type": "user",
            "risk_level": graph_user.risk_level,
            "details": f"Risk {graph_user.risk_score:.1f} · {graph_user.risk_level}",
        }
        identifiers = (
            ("email", graph_user.email.lower(), "Email match"),
            ("phone", graph_user.phone_hash, "Phone hash"),
            ("address", graph_user.address_hash, "Address hash"),
        )
        for identifier_type, identifier_value, label in identifiers:
            if not identifier_value:
                continue
            identifier_id = f"identifier-{identifier_type}-{_hash_identifier(identifier_type, identifier_value)[:20]}"
            nodes[identifier_id] = {
                "id": identifier_id,
                "label": label,
                "type": identifier_type,
                "details": f"Shared {identifier_type} identifier; value withheld",
            }
            edges.append({"source": user_node_id, "target": identifier_id, "label": "matches"})

    devices = db.query(Device).join(UserDevice).filter(UserDevice.user_id.in_(allowed_user_ids)).all() if allowed_user_ids else []
    ips = db.query(IPAddress).join(UserIPAddress).filter(UserIPAddress.user_id.in_(allowed_user_ids)).all() if allowed_user_ids else []
    for device in devices:
        nodes[f"device-{device.id}"] = {"id": f"device-{device.id}", "label": device.device_type.title(), "type": "device", "details": f"{device.operating_system} · {device.browser} · {device.device_fingerprint[:18]}"}
    for ip_record in ips:
        nodes[f"ip-{ip_record.id}"] = {"id": f"ip-{ip_record.id}", "label": f"{ip_record.country} / {ip_record.region}", "type": "ip", "details": f"{ip_record.isp} · reputation {ip_record.reputation_score:.2f}"}
    device_links = db.query(UserDevice).filter(UserDevice.user_id.in_(allowed_user_ids)).all() if allowed_user_ids else []
    ip_links = db.query(UserIPAddress).filter(UserIPAddress.user_id.in_(allowed_user_ids)).all() if allowed_user_ids else []
    edges.extend({"source": f"user-{link.user_id}", "target": f"device-{link.device_id}", "label": "uses"} for link in device_links)
    edges.extend({"source": f"user-{link.user_id}", "target": f"ip-{link.ip_id}", "label": "connects from"} for link in ip_links)
    unique_edges = {(edge["source"], edge["target"], edge["label"]): edge for edge in edges}
    return {"nodes": list(nodes.values()), "edges": list(unique_edges.values())}


@app.get("/investigations")
def list_investigations(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> list[dict[str, Any]]:
    records = db.query(Investigation).order_by(Investigation.updated_at.desc()).all()
    return [
        {
            "id": record.id,
            "user_id": record.user_id,
            "username": record.user.username if record.user else "Unknown",
            "email": record.user.email if record.user else "",
            "risk_score": record.user.risk_score if record.user else 0,
            "risk_level": record.user.risk_level if record.user else "LOW",
            "status": record.status,
            "decision": record.decision,
            "notes": record.notes,
            "analyst_id": record.analyst_id,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }
        for record in records
    ]


@app.post("/investigations", status_code=status.HTTP_201_CREATED)
def open_investigation(payload: dict[str, Any], db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    user_id = payload.get("user_id")
    user = get_user_by_id(db, user_id) if isinstance(user_id, int) else None
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    investigation = Investigation(user_id=user_id, analyst_id=current_user.id, status="open", notes="", decision="pending")
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    return {"id": investigation.id, "user_id": user_id, "status": investigation.status, "decision": investigation.decision}


@app.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    record = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")
    indicators = user_indicators(record.user_id, db, current_user)
    timeline = user_timeline(record.user_id, db, current_user)
    graph = user_graph(record.user_id, db, current_user)
    return {
        "id": record.id,
        "user_id": record.user_id,
        "username": record.user.username if record.user else "Unknown",
        "email": record.user.email if record.user else "",
        "risk_score": record.user.risk_score if record.user else 0,
        "risk_level": record.user.risk_level if record.user else "LOW",
        "status": record.status,
        "decision": record.decision,
        "notes": record.notes,
        "analyst_id": record.analyst_id,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "indicators": indicators,
        "timeline": timeline,
        "graph": graph,
    }


@app.patch("/investigations/{investigation_id}")
def update_investigation(investigation_id: int, payload: dict[str, Any], db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    record = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if "status" in payload:
        if payload["status"] not in {"open", "under_review", "verification_required", "resolved", "false_positive"}:
            raise HTTPException(status_code=422, detail="Unsupported investigation status")
        record.status = payload["status"]
    if "decision" in payload:
        if payload["decision"] not in {"pending", "confirmed", "cleared", "false_positive"}:
            raise HTTPException(status_code=422, detail="Unsupported investigation decision")
        record.decision = payload["decision"]
    if "notes" in payload:
        record.notes = str(payload["notes"])[:10000]
    record.analyst_id = current_user.id
    record.updated_at = datetime.utcnow()
    db.commit()
    return {"id": record.id, "status": record.status, "decision": record.decision, "notes": record.notes, "updated_at": record.updated_at}


@app.post("/users/{user_id}/request-verification")
def request_verification(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.identity_verification_status = "verification_required"
    user.status = "investigating"
    db.commit()
    return {"user_id": user_id, "identity_verification_status": user.identity_verification_status}


@app.get("/demo/scenarios")
def list_demo_scenarios(current_user: User = Depends(get_current_user)) -> list[dict[str, str]]:
    return [{"id": scenario_id, "label": label} for scenario_id, label in SCENARIOS.items()]


@app.post("/demo/scenarios/{scenario}", status_code=status.HTTP_201_CREATED)
def create_demo_scenario(scenario: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    try:
        return generate_demo_scenario(db, scenario)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/admin/health")
def admin_health(current_user: User = Depends(require_role("ADMIN"))):
    return {"status": "admin-ok", "user": current_user.username}


@app.exception_handler(Exception)
async def handle_exception(request, exc):
    return JSONResponse(status_code=500, content={"detail": "An internal error occurred."})
