import json
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models import BehaviorEvent, Device, IPAddress, Observation, ObservationActivity, RiskAssessment, User, UserDevice, UserIPAddress
from app.risk_scoring import calculate_risk


def sync_observation(db: Session, user: User, risk_score: float, risk_level: str, reasons: list[str]) -> Observation | None:
    observation = (
        db.query(Observation)
        .filter(Observation.user_id == user.id, Observation.status == "ACTIVE")
        .first()
    )
    now = datetime.utcnow()
    if risk_level in {"MEDIUM", "HIGH", "CRITICAL"}:
        if observation is None:
            observation = Observation(user_id=user.id, started_at=now)
            db.add(observation)
        observation.risk_score = risk_score
        observation.risk_level = risk_level
        observation.reasons = json.dumps(reasons)
        observation.updated_at = now
        observation.status = "ACTIVE"
    elif observation is not None:
        observation.status = "RESOLVED"
        observation.updated_at = now
    return observation


def record_observation_activity(
    db: Session,
    user_id: int,
    activity_type: str,
    details: str = "",
) -> ObservationActivity | None:
    observation = (
        db.query(Observation)
        .filter(Observation.user_id == user_id, Observation.status == "ACTIVE")
        .first()
    )
    if observation is None:
        return None
    activity = ObservationActivity(
        observation_id=observation.id,
        user_id=user_id,
        activity_type=activity_type,
        details=details,
    )
    db.add(activity)
    db.commit()
    db.refresh(activity)
    return activity


def create_user(
    db: Session,
    username: str,
    email: str,
    password_hash: str,
    phone_hash: str,
    address_hash: str,
    role: str = "USER",
) -> User:
    user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        phone_hash=phone_hash,
        address_hash=address_hash,
        role=role,
        identity_verification_status="unverified",
        risk_score=0.0,
        risk_level="LOW",
        status="active",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_dashboard_stats(db: Session) -> dict:
    total_users = db.query(User).count()
    high_risk = db.query(User).filter(User.risk_level == "HIGH").count()
    critical_risk = db.query(User).filter(User.risk_level == "CRITICAL").count()
    medium_risk = db.query(User).filter(User.risk_level == "MEDIUM").count()
    low_risk = db.query(User).filter(User.risk_level == "LOW").count()
    under_investigation = db.query(User).filter(User.status == "investigating").count()
    return {
        "total_users": total_users,
        "high_risk": high_risk,
        "critical_risk": critical_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
        "under_investigation": under_investigation,
    }


def get_dashboard_signals(db: Session) -> dict[str, int]:
    recent_cutoff = datetime.utcnow() - timedelta(hours=1)
    active_sessions = (
        db.query(BehaviorEvent.session_id)
        .filter(BehaviorEvent.timestamp >= recent_cutoff, BehaviorEvent.session_id.isnot(None))
        .distinct()
        .count()
    )
    suspicious_devices = (
        db.query(UserDevice.device_id)
        .join(User, User.id == UserDevice.user_id)
        .filter(User.risk_level.in_(("HIGH", "CRITICAL")))
        .group_by(UserDevice.device_id)
        .count()
    )
    suspicious_ips = (
        db.query(IPAddress.id)
        .join(UserIPAddress, UserIPAddress.ip_id == IPAddress.id)
        .filter(
            (IPAddress.reputation_score <= 0.3)
            | IPAddress.vpn_detected.is_(True)
            | IPAddress.proxy_detected.is_(True)
            | IPAddress.tor_detected.is_(True)
        )
        .distinct()
        .count()
    )

    risk_levels = {user.id: user.risk_level for user in db.query(User.id, User.risk_level).all()}
    adjacency: dict[int, set[int]] = {}
    for link_table, entity_column in ((UserDevice, UserDevice.device_id), (UserIPAddress, UserIPAddress.ip_id)):
        grouped: dict[int, set[int]] = {}
        for user_id, entity_id in db.query(link_table.user_id, entity_column).all():
            grouped.setdefault(entity_id, set()).add(user_id)
        for users in grouped.values():
            for user_id in users:
                adjacency.setdefault(user_id, set()).update(users - {user_id})

    visited: set[int] = set()
    fraud_clusters = 0
    for user_id in adjacency:
        if user_id in visited:
            continue
        component: set[int] = set()
        stack = [user_id]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            component.add(current)
            stack.extend(adjacency.get(current, set()) - visited)
        risky_members = sum(risk_levels.get(member) in {"HIGH", "CRITICAL"} for member in component)
        if len(component) >= 3 and risky_members >= 1:
            fraud_clusters += 1

    return {
        "active_sessions": active_sessions,
        "suspicious_devices": suspicious_devices,
        "suspicious_ips": suspicious_ips,
        "fraud_clusters": fraud_clusters,
    }


def create_risk_assessment(
    db: Session,
    user_id: int,
    model_score: float,
    rule_score: float,
    graph_score: float,
    behavior_score: float,
    anomaly_score: float,
) -> RiskAssessment:
    fusion = calculate_risk(
        {"_signal_overrides": {
            "identity": rule_score, "device": graph_score, "network": graph_score,
            "behavior": behavior_score, "temporal": rule_score, "graph": graph_score,
        }},
        model_score,
        anomaly_score,
    )
    risk_score = fusion["risk_score"]
    risk_level = fusion["risk_level"]

    assessment = RiskAssessment(
        user_id=user_id,
        risk_score=risk_score,
        risk_level=risk_level,
        model_score=model_score,
        rule_score=rule_score,
        graph_score=graph_score,
        behavior_score=behavior_score,
        anomaly_score=anomaly_score,
        created_at=datetime.utcnow(),
    )
    db.add(assessment)
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.risk_score = risk_score
        user.risk_level = risk_level
        sync_observation(db, user, risk_score, risk_level, [])
    db.commit()
    db.refresh(assessment)

    return assessment


def list_risk_assessments(db: Session):
    return db.query(RiskAssessment).order_by(RiskAssessment.created_at.desc()).all()


def create_behavior_event(db: Session, user_id: int, session_id: str, event_type: str, duration: float, event_metadata: str):
    event = BehaviorEvent(
        user_id=user_id,
        session_id=session_id,
        event_type=event_type,
        duration=duration,
        event_metadata=event_metadata,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()
