from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.data_generation import generate_dataset
from app.features.feature_engineering import build_user_feature_vector
from app.models import BehaviorEvent, Device, IdentityChange, IPAddress, User, UserDevice, UserIPAddress
from app.database import Base


def build_test_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session(), engine


def test_generator_creates_connected_records():
    session, _ = build_test_session()
    try:
        counts = generate_dataset(session, users=80, fraud_ratio=0.2, seed=7, reset=True)
        assert counts["users"] >= 80
        assert counts["devices"] > 0
        assert counts["ips"] > 0
        assert counts["user_devices"] > 0
        assert counts["user_ips"] > 0
        assert counts["behavior_events"] > 0
        assert counts["identity_changes"] > 0
        assert session.query(User).count() > 0
        assert session.query(Device).count() > 0
        assert session.query(IPAddress).count() > 0
        assert session.query(UserDevice).count() > 0
        assert session.query(UserIPAddress).count() > 0
        assert session.query(BehaviorEvent).count() > 0
        assert session.query(IdentityChange).count() > 0
    finally:
        session.close()


def test_shared_wifi_does_not_create_obvious_suspicion():
    session, _ = build_test_session()
    try:
        user = User(
            username="shared_wifi_user",
            email="shared_wifi@example.com",
            password_hash="hashed-password",
            phone_hash="phone_hash",
            address_hash="address_hash",
            role="USER",
            created_at=datetime.utcnow() - timedelta(days=40),
            identity_verification_status="verified",
            risk_level="LOW",
            status="active",
        )
        session.add(user)
        session.flush()

        shared_ip = IPAddress(ip_hash="shared-ip-1", country="US", region="NA", reputation_score=0.72, vpn_detected=False, proxy_detected=False, tor_detected=False)
        session.add(shared_ip)
        session.flush()

        for i in range(3):
            other_user = User(
                username=f"wifi_peer_{i}",
                email=f"wifi_peer_{i}@example.com",
                password_hash="hashed-password",
                phone_hash=f"phone_{i}",
                address_hash=f"addr_{i}",
                role="USER",
                created_at=datetime.utcnow() - timedelta(days=20),
                identity_verification_status="verified",
                risk_level="LOW",
                status="active",
            )
            session.add(other_user)
            session.flush()
            session.add(UserIPAddress(user_id=other_user.id, ip_id=shared_ip.id, usage_count=5, first_seen=datetime.utcnow() - timedelta(days=10)))
        session.add(UserIPAddress(user_id=user.id, ip_id=shared_ip.id, usage_count=8, first_seen=datetime.utcnow() - timedelta(days=10)))
        session.commit()

        features = build_user_feature_vector(user.id, session)
        assert features["ip_account_count"] >= 2
        assert features["vpn_flag"] is False
        assert features["proxy_flag"] is False
        assert features["tor_flag"] is False
        assert features["ip_reputation"] >= 0.5
    finally:
        session.close()


def test_email_domain_reuse_is_not_exact_email_reuse():
    session, _ = build_test_session()
    try:
        accounts = [
            User(username="john", email="john@gmail.com", password_hash="x", phone_hash="phone-john", address_hash="address-john"),
            User(username="alex", email="alex@gmail.com", password_hash="x", phone_hash="phone-alex", address_hash="address-alex"),
            User(username="john_case", email="JOHN@gmail.com", password_hash="x", phone_hash="phone-case", address_hash="address-case"),
        ]
        session.add_all(accounts)
        session.commit()

        john = build_user_feature_vector(accounts[0].id, session)
        alex = build_user_feature_vector(accounts[1].id, session)
        assert john["email_exact_reuse_count"] == 1
        assert john["email_domain_reuse_count"] == 1
        assert alex["email_exact_reuse_count"] == 0
        assert alex["email_domain_reuse_count"] == 2
    finally:
        session.close()


def test_identity_farm_has_stronger_risk_signals():
    session, _ = build_test_session()
    try:
        base_time = datetime.utcnow() - timedelta(hours=2)
        for index in range(8):
            user = User(
                username=f"farm_{index}",
                email=f"farm_{index}@example.com",
                password_hash="hashed-password",
                phone_hash=f"farm_phone_{index}",
                address_hash=f"farm_addr_{index}",
                role="USER",
                created_at=base_time - timedelta(minutes=index * 5),
                identity_verification_status="pending",
                risk_level="MEDIUM",
                status="investigating",
            )
            session.add(user)
            session.flush()
            device = Device(device_fingerprint=f"farm_device_{index}")
            session.add(device)
            session.flush()
            session.add(UserDevice(user_id=user.id, device_id=device.id, usage_count=25, first_seen=base_time))
            ip_record = IPAddress(ip_hash=f"farm_ip_{index}", country="US", region="NA", reputation_score=0.18, vpn_detected=True, proxy_detected=True)
            session.add(ip_record)
            session.flush()
            session.add(UserIPAddress(user_id=user.id, ip_id=ip_record.id, usage_count=15, first_seen=base_time))
            session.add(IdentityChange(user_id=user.id, field_changed="phone", old_value_hash="old", new_value_hash="new", timestamp=base_time))
        session.commit()

        first_user = session.query(User).order_by(User.id.asc()).first()
        features = build_user_feature_vector(first_user.id, session)
        assert features["device_account_count"] >= 1
        assert features["ip_account_count"] >= 1
        assert features["account_creation_burst"] >= 2
    finally:
        session.close()


def test_bot_behavior_has_high_actions_per_minute_and_short_intervals():
    session, _ = build_test_session()
    try:
        user = User(
            username="bot_user",
            email="bot_user@example.com",
            password_hash="hashed-password",
            phone_hash="bot_phone",
            address_hash="bot_address",
            role="USER",
            created_at=datetime.utcnow() - timedelta(days=14),
            identity_verification_status="pending",
            risk_level="HIGH",
            status="investigating",
        )
        session.add(user)
        session.flush()

        start_time = datetime.utcnow() - timedelta(minutes=12)
        for idx in range(120):
            session.add(
                BehaviorEvent(
                    user_id=user.id,
                    session_id="bot-session",
                    event_type="PAGE_VIEW",
                    timestamp=start_time + timedelta(seconds=idx * 7),
                    duration=4.0,
                    event_metadata="{\"source\": \"bot\"}",
                )
            )
        session.commit()

        features = build_user_feature_vector(user.id, session)
        assert features["actions_per_minute"] > 5
        assert features["average_action_interval"] < 60
    finally:
        session.close()


def test_rapid_identity_changes_increase_recent_counters():
    session, _ = build_test_session()
    try:
        user = User(
            username="rapid_change_user",
            email="rapid_change@example.com",
            password_hash="hashed-password",
            phone_hash="rapid_phone",
            address_hash="rapid_address",
            role="USER",
            created_at=datetime.utcnow() - timedelta(days=15),
            identity_verification_status="pending",
            risk_level="MEDIUM",
            status="investigating",
        )
        session.add(user)
        session.flush()

        base_time = datetime.utcnow()
        for field_name, offset in [("phone", 10), ("email", 20), ("address", 38), ("device", 50)]:
            session.add(
                IdentityChange(
                    user_id=user.id,
                    field_changed=field_name,
                    old_value_hash=f"old_{field_name}",
                    new_value_hash=f"new_{field_name}",
                    timestamp=base_time - timedelta(minutes=offset),
                )
            )
        session.commit()

        features = build_user_feature_vector(user.id, session)
        assert features["identity_change_count"] >= 4
        assert features["identity_changes_last_24h"] >= 4
        assert features["recent_identity_changes"] >= 4
    finally:
        session.close()
