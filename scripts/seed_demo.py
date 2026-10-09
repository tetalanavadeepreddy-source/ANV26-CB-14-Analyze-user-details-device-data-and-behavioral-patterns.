import os
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.auth import get_password_hash
from app.database import Base
from app.models import RiskAssessment, User

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./identityguard.db")
DEMO_PASSWORD = "DemoPass!123"
DEMO_EMAILS = ("analyst@demo.local", "device@demo.local", "farm@demo.local")
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)

with Session(engine) as session:
    if session.query(User).count() == 0:
        password_hash = get_password_hash(DEMO_PASSWORD)
        users = [
            User(
                username="analyst_demo",
                email="analyst@demo.local",
                password_hash=password_hash,
                phone_hash="hash_phone_1",
                address_hash="hash_address_1",
                role="ANALYST",
                risk_score=32.0,
                risk_level="LOW",
                status="active",
            ),
            User(
                username="shared_device_user",
                email="device@demo.local",
                password_hash=password_hash,
                phone_hash="hash_phone_2",
                address_hash="hash_address_2",
                role="USER",
                risk_score=62.0,
                risk_level="MEDIUM",
                status="active",
            ),
            User(
                username="synthetic_farm_01",
                email="farm@demo.local",
                password_hash=password_hash,
                phone_hash="hash_phone_3",
                address_hash="hash_address_3",
                role="USER",
                risk_score=88.0,
                risk_level="HIGH",
                status="investigating",
            ),
        ]
        session.add_all(users)
        session.commit()

        for user in users:
            session.add(
                RiskAssessment(
                    user_id=user.id,
                    risk_score=user.risk_score,
                    risk_level=user.risk_level,
                    model_score=user.risk_score,
                    rule_score=max(0.0, user.risk_score - 12),
                    graph_score=max(0.0, user.risk_score - 8),
                    behavior_score=max(0.0, user.risk_score - 20),
                    anomaly_score=max(0.0, user.risk_score - 16),
                    created_at=datetime.utcnow(),
                )
            )
        session.commit()

    for user in session.query(User).filter(User.email.in_(DEMO_EMAILS)):
        if user.password_hash == "hashed-demo-password":
            user.password_hash = get_password_hash(DEMO_PASSWORD)
    session.commit()

print("Demo data initialized.")
