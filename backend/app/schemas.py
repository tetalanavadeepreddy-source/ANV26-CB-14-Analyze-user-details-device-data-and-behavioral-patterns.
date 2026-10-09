from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, IPvAnyAddress


class UserCreate(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    username: str
    email: EmailStr
    password: str
    phone_hash: str = ""
    address_hash: str = ""
    role: str = "USER"


class UserLogin(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    email: EmailStr
    password: str


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: int
    username: str
    email: EmailStr
    role: str
    phone_hash: str
    address_hash: str
    created_at: datetime
    identity_verification_status: str
    risk_score: float
    risk_level: str
    status: str


class RiskAssessmentCreate(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    user_id: int
    model_score: float = Field(default=0.0)
    rule_score: float = Field(default=0.0)
    graph_score: float = Field(default=0.0)
    behavior_score: float = Field(default=0.0)
    anomaly_score: float = Field(default=0.0)


class RiskAssessmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: int
    user_id: int
    risk_score: float
    risk_level: str
    model_score: float
    rule_score: float
    graph_score: float
    behavior_score: float
    anomaly_score: float
    created_at: datetime


class RiskEventInput(BaseModel):
    event_type: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z][A-Za-z0-9_]{0,79}$")
    timestamp: datetime | None = None
    duration: float = Field(default=0.0, ge=0, le=86400)


class RiskAnalyzeRequest(BaseModel):
    user_id: int = Field(ge=1)
    device_id: str | None = Field(default=None, min_length=1, max_length=120)
    ip: IPvAnyAddress | None = None
    session_id: str | None = Field(default=None, min_length=1, max_length=120)
    events: list[RiskEventInput] = Field(default_factory=list, max_length=500)


class RiskReasonRead(BaseModel):
    feature: str
    signal: str
    description: str
    feature_value: float | int | str | bool
    signal_points: float
    weighted_points: float


class RiskIndicatorRead(BaseModel):
    id: int | None = None
    indicator_type: str
    description: str
    severity: str
    feature_value: str


class RiskAnalyzeResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    assessment_id: int
    prediction_id: int
    user_id: int
    session_id: str | None
    risk_score: float = Field(ge=0, le=100)
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    decision: Literal["ALLOW", "MONITOR", "REVIEW", "ESCALATE"]
    confidence: float = Field(ge=0, le=100)
    evidence_coverage: float = Field(ge=0, le=100)
    ml_score: float = Field(ge=0, le=100)
    ml_probability: float = Field(ge=0, le=1)
    model_score: float = Field(ge=0, le=100)
    model_status: str
    anomaly_score: float = Field(ge=0, le=100)
    rule_score: float = Field(ge=0, le=100)
    graph_score: float = Field(ge=0, le=100)
    behavior_score: float = Field(ge=0, le=100)
    signal_scores: dict[str, float]
    weights: dict[str, float]
    top_reasons: list[RiskReasonRead]
    mitigating_reasons: list[str]
    explanation_method: str
    features: dict[str, Any]
    indicators: list[RiskIndicatorRead]
    model_version: str


class InvestigatorFeedbackCreate(BaseModel):
    action: Literal["CONFIRM_FRAUD", "FALSE_POSITIVE"]
    note: str = Field(default="", max_length=2000)


class DashboardStats(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    total_users: int
    high_risk: int
    critical_risk: int = 0
    medium_risk: int
    low_risk: int
    under_investigation: int


class EventCreate(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    user_id: int
    session_id: str
    event_type: str
    duration: float = 0.0
    event_metadata: Optional[str] = "{}"


class ObservationStatusUpdate(BaseModel):
    status: Literal["ACTIVE", "RESOLVED"]
