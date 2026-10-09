from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    phone_hash = Column(String(255), nullable=False)
    address_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="USER", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    identity_verification_status = Column(String(50), default="unverified")
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="LOW")
    status = Column(String(20), default="active")

    risk_assessments = relationship("RiskAssessment", back_populates="user")
    behavior_events = relationship("BehaviorEvent", back_populates="user")
    identity_changes = relationship("IdentityChange", back_populates="user")
    investigations = relationship("Investigation", back_populates="user")
    user_devices = relationship("UserDevice", back_populates="user")
    user_ips = relationship("UserIPAddress", back_populates="user")


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    device_fingerprint = Column(String(255), unique=True, index=True, nullable=False)
    device_type = Column(String(50), default="desktop")
    operating_system = Column(String(50), default="windows")
    browser = Column(String(50), default="chrome")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    user_links = relationship("UserDevice", back_populates="device")


class IPAddress(Base):
    __tablename__ = "ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_hash = Column(String(255), unique=True, index=True, nullable=False)
    country = Column(String(80), default="US")
    region = Column(String(80), default="NA")
    isp = Column(String(80), default="broadband")
    vpn_detected = Column(Boolean, default=False)
    proxy_detected = Column(Boolean, default=False)
    tor_detected = Column(Boolean, default=False)
    reputation_score = Column(Float, default=0.5)

    user_links = relationship("UserIPAddress", back_populates="ip_address")


class UserDevice(Base):
    __tablename__ = "user_devices"
    __table_args__ = (
        Index("ix_user_devices_device_id", "device_id"),
        Index("ix_user_devices_user_id", "user_id"),
    )

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id"), primary_key=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    usage_count = Column(Integer, default=0)

    user = relationship("User", back_populates="user_devices")
    device = relationship("Device", back_populates="user_links")


class UserIPAddress(Base):
    __tablename__ = "user_ips"
    __table_args__ = (
        Index("ix_user_ips_ip_id", "ip_id"),
        Index("ix_user_ips_user_id", "user_id"),
    )

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    ip_id = Column(Integer, ForeignKey("ips.id"), primary_key=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    usage_count = Column(Integer, default=0)

    user = relationship("User", back_populates="user_ips")
    ip_address = relationship("IPAddress", back_populates="user_links")


class BehaviorEvent(Base):
    __tablename__ = "behavior_events"
    __table_args__ = (
        Index("ix_behavior_events_user_type_timestamp", "user_id", "event_type", "timestamp"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    session_id = Column(String(120), index=True)
    event_type = Column(String(80), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    duration = Column(Float, default=0.0)
    event_metadata = Column(Text, default="{}")

    user = relationship("User", back_populates="behavior_events")


class IdentityChange(Base):
    __tablename__ = "identity_changes"
    __table_args__ = (
        Index("ix_identity_changes_user_timestamp", "user_id", "timestamp"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    field_changed = Column(String(80), index=True)
    old_value_hash = Column(String(255), nullable=False)
    new_value_hash = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="identity_changes")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="LOW")
    model_score = Column(Float, default=0.0)
    rule_score = Column(Float, default=0.0)
    graph_score = Column(Float, default=0.0)
    behavior_score = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="risk_assessments")
    indicators = relationship("RiskIndicator", back_populates="risk_assessment")


class RiskPrediction(Base):
    __tablename__ = "risk_predictions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=True)
    session_id = Column(String(120), index=True, nullable=True)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)
    decision = Column(String(20), nullable=False)
    confidence = Column(Float, nullable=False)
    ml_score = Column(Float, nullable=False)
    anomaly_score = Column(Float, nullable=False)
    model_version = Column(String(80), nullable=False)
    features = Column(Text, nullable=False)
    top_reasons = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")
    feedback = relationship("InvestigatorFeedback", back_populates="prediction", cascade="all, delete-orphan")


class InvestigatorFeedback(Base):
    __tablename__ = "investigator_feedback"

    id = Column(Integer, primary_key=True, index=True)
    prediction_id = Column(Integer, ForeignKey("risk_predictions.id"), index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=True)
    analyst_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    actual_label = Column(Integer, nullable=False)
    feedback_action = Column(String(30), nullable=False)
    features = Column(Text, nullable=False)
    note = Column(Text, default="", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    prediction = relationship("RiskPrediction", back_populates="feedback")
    analyst = relationship("User", foreign_keys=[analyst_id])


class RiskIndicator(Base):
    __tablename__ = "risk_indicators"

    id = Column(Integer, primary_key=True, index=True)
    risk_assessment_id = Column(Integer, ForeignKey("risk_assessments.id"))
    indicator_type = Column(String(80))
    description = Column(Text)
    severity = Column(String(20), default="MEDIUM")
    feature_value = Column(String(255), default="")

    risk_assessment = relationship("RiskAssessment", back_populates="indicators")


class Observation(Base):
    __tablename__ = "observations"
    __table_args__ = (
        Index(
            "uq_observations_active_user",
            "user_id",
            unique=True,
            sqlite_where=text("status = 'ACTIVE'"),
            postgresql_where=text("status = 'ACTIVE'"),
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)
    reasons = Column(Text, default="[]", nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(20), default="ACTIVE", index=True, nullable=False)

    user = relationship("User")
    activities = relationship("ObservationActivity", back_populates="observation", cascade="all, delete-orphan")


class ObservationActivity(Base):
    __tablename__ = "observation_activities"
    __table_args__ = (Index("ix_observation_activities_observation_time", "observation_id", "timestamp"),)

    id = Column(Integer, primary_key=True, index=True)
    observation_id = Column(Integer, ForeignKey("observations.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    activity_type = Column(String(80), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    details = Column(Text, default="", nullable=False)

    observation = relationship("Observation", back_populates="activities")


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    analyst_id = Column(Integer, nullable=True)
    status = Column(String(30), default="open")
    notes = Column(Text, default="")
    decision = Column(String(30), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="investigations")
