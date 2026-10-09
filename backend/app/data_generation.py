from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.auth import get_password_hash
from app.models import BehaviorEvent, Device, IdentityChange, IPAddress, User, UserDevice, UserIPAddress

EVENT_TYPES = [
    "LOGIN",
    "LOGOUT",
    "PAGE_VIEW",
    "SEARCH",
    "PROFILE_UPDATE",
    "PASSWORD_CHANGE",
    "EMAIL_CHANGE",
    "PHONE_CHANGE",
    "DEVICE_CHANGE",
    "FAILED_LOGIN",
    "CHECKOUT",
    "TRANSACTION",
]


def _hash_value(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _create_user_record(
    db: Session,
    username: str,
    email: str,
    created_at: datetime,
    role: str = "USER",
    risk_level: str = "LOW",
    status: str = "active",
    verification_status: str = "verified",
) -> User:
    user = User(
        username=username,
        email=email,
        password_hash=get_password_hash("DemoPass123!"),
        phone_hash=_hash_value(f"phone-{username}"),
        address_hash=_hash_value(f"addr-{username}"),
        role=role,
        created_at=created_at,
        identity_verification_status=verification_status,
        risk_score=0.0 if risk_level == "LOW" else 55.0 if risk_level == "MEDIUM" else 85.0,
        risk_level=risk_level,
        status=status,
    )
    db.add(user)
    db.flush()
    return user


def _create_device(db: Session, fingerprint: str, device_type: str = "desktop", os_name: str = "windows", browser: str = "chrome") -> Device:
    device = Device(
        device_fingerprint=fingerprint,
        device_type=device_type,
        operating_system=os_name,
        browser=browser,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db.add(device)
    db.flush()
    return device


def _create_ip(db: Session, ip_value: str, country: str = "US", region: str = "NA", suspicious: bool = False) -> IPAddress:
    ip_record = IPAddress(
        ip_hash=_hash_value(ip_value),
        country=country,
        region=region,
        isp="broadband" if not suspicious else "residential-proxy",
        vpn_detected=suspicious and random.random() < 0.25,
        proxy_detected=suspicious and random.random() < 0.35,
        tor_detected=suspicious and random.random() < 0.12,
        reputation_score=0.2 if suspicious else 0.75,
    )
    db.add(ip_record)
    db.flush()
    return ip_record


def _link_user_to_device(db: Session, user_id: int, device_id: int, usage_count: int = 1, first_seen: datetime | None = None) -> None:
    link = UserDevice(
        user_id=user_id,
        device_id=device_id,
        first_seen=first_seen or datetime.utcnow(),
        last_seen=datetime.utcnow(),
        usage_count=usage_count,
    )
    db.add(link)


def _link_user_to_ip(db: Session, user_id: int, ip_id: int, usage_count: int = 1, first_seen: datetime | None = None) -> None:
    link = UserIPAddress(
        user_id=user_id,
        ip_id=ip_id,
        first_seen=first_seen or datetime.utcnow(),
        last_seen=datetime.utcnow(),
        usage_count=usage_count,
    )
    db.add(link)


def _create_identity_change(db: Session, user_id: int, field_name: str, timestamp: datetime) -> None:
    change = IdentityChange(
        user_id=user_id,
        field_changed=field_name,
        old_value_hash=_hash_value(f"old-{field_name}-{user_id}-{timestamp.isoformat()}"),
        new_value_hash=_hash_value(f"new-{field_name}-{user_id}-{timestamp.isoformat()}"),
        timestamp=timestamp,
    )
    db.add(change)


def _create_behavior_events(db: Session, user_id: int, start_time: datetime, event_count: int, rng: random.Random, suspicious: bool = False) -> None:
    for idx in range(event_count):
        event_type = rng.choice(EVENT_TYPES)
        interval = rng.randint(20, 180) if suspicious else rng.randint(120, 3600)
        timestamp = start_time + timedelta(seconds=idx * interval)
        event = BehaviorEvent(
            user_id=user_id,
            session_id=f"session-{user_id}-{start_time.date()}",
            event_type=event_type,
            timestamp=timestamp,
            duration=max(5.0, float(rng.randint(10, 300))) if event_type not in {"FAILED_LOGIN"} else 2.0,
            event_metadata=str({"source": "synthetic", "suspicious": suspicious, "event_index": idx}),
        )
        db.add(event)


def _create_normal_user(db: Session, user_index: int, rng: random.Random, base_time: datetime) -> User:
    created_at = base_time - timedelta(days=rng.randint(7, 365), minutes=rng.randint(0, 1440))
    user = _create_user_record(
        db,
        username=f"normal_{user_index}",
        email=f"normal_{user_index}@example.com",
        created_at=created_at,
        role="USER",
        risk_level="LOW",
        status="active",
        verification_status="verified",
    )

    device_count = rng.randint(1, 3)
    for device_index in range(device_count):
        device = _create_device(db, f"device-normal-{user.id}-{device_index}", device_type=rng.choice(["desktop", "laptop", "tablet"]))
        _link_user_to_device(db, user.id, device.id, usage_count=rng.randint(2, 12), first_seen=created_at)

    for ip_index in range(rng.randint(1, 3)):
        ip_record = _create_ip(db, f"10.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}", country=rng.choice(["US", "GB", "CA", "IN", "AU"]), region=rng.choice(["NA", "EU", "APAC"]))
        _link_user_to_ip(db, user.id, ip_record.id, usage_count=rng.randint(1, 8), first_seen=created_at)

    _create_behavior_events(db, user.id, created_at + timedelta(hours=2), rng.randint(20, 90), rng, suspicious=False)
    if rng.random() < 0.2:
        _create_identity_change(db, user.id, rng.choice(["email", "phone", "address"]), created_at + timedelta(days=rng.randint(10, 180)))

    return user


def _create_identity_farm_cluster(db: Session, cluster_index: int, base_time: datetime, rng: random.Random) -> list[User]:
    farm_users: list[User] = []
    shared_devices = [
        _create_device(db, f"device-farm-{cluster_index}-1", device_type="desktop", os_name="windows", browser="chrome"),
        _create_device(db, f"device-farm-{cluster_index}-2", device_type="laptop", os_name="macos", browser="safari"),
    ]
    shared_ips = [
        _create_ip(db, f"198.51.{cluster_index}.{rng.randint(10, 200)}", country="US", region="NA", suspicious=True),
        _create_ip(db, f"198.51.{cluster_index + 2}.{rng.randint(10, 200)}", country="US", region="NA", suspicious=True),
    ]

    for user_index in range(1, 11):
        created_at = base_time - timedelta(minutes=rng.randint(5, 180))
        user = _create_user_record(
            db,
            username=f"farm_{cluster_index}_{user_index}",
            email=f"farm_{cluster_index}_{user_index}@example.com",
            created_at=created_at,
            role="USER",
            risk_level="MEDIUM",
            status="investigating",
            verification_status="pending",
        )
        farm_users.append(user)
        for device in shared_devices:
            _link_user_to_device(db, user.id, device.id, usage_count=rng.randint(4, 15), first_seen=created_at)
        for ip_record in shared_ips:
            _link_user_to_ip(db, user.id, ip_record.id, usage_count=rng.randint(2, 12), first_seen=created_at)
        _create_behavior_events(db, user.id, created_at + timedelta(minutes=3), rng.randint(15, 60), rng, suspicious=True)
        _create_identity_change(db, user.id, "email", created_at + timedelta(minutes=rng.randint(10, 45)))
        _create_identity_change(db, user.id, "phone", created_at + timedelta(minutes=rng.randint(20, 75)))

    return farm_users


def _create_bot_user(db: Session, user_index: int, base_time: datetime, rng: random.Random) -> User:
    created_at = base_time - timedelta(days=rng.randint(7, 120))
    user = _create_user_record(
        db,
        username=f"bot_{user_index}",
        email=f"bot_{user_index}@example.com",
        created_at=created_at,
        role="USER",
        risk_level="HIGH",
        status="investigating",
        verification_status="pending",
    )

    device = _create_device(db, f"device-bot-{user.id}", device_type="desktop", os_name="linux", browser="chrome")
    _link_user_to_device(db, user.id, device.id, usage_count=200, first_seen=created_at)

    ip_record = _create_ip(db, f"203.0.113.{user_index}", country="US", region="NA", suspicious=True)
    _link_user_to_ip(db, user.id, ip_record.id, usage_count=150, first_seen=created_at)

    start_time = created_at + timedelta(hours=1)
    for idx in range(120):
        timestamp = start_time + timedelta(seconds=idx * 9)
        db.add(
            BehaviorEvent(
                user_id=user.id,
                session_id=f"bot-session-{user.id}",
                event_type=rng.choice(["LOGIN", "PAGE_VIEW", "SEARCH", "PROFILE_UPDATE", "CHECKOUT", "TRANSACTION"]),
                timestamp=timestamp,
                duration=5.0,
                event_metadata=str({"source": "bot", "interval_seconds": 9}),
            )
        )
    return user


def _create_rapid_identity_mutation_user(db: Session, user_index: int, base_time: datetime, rng: random.Random) -> User:
    created_at = base_time - timedelta(days=rng.randint(3, 18))
    user = _create_user_record(
        db,
        username=f"rapid_change_{user_index}",
        email=f"rapid_change_{user_index}@example.com",
        created_at=created_at,
        role="USER",
        risk_level="MEDIUM",
        status="investigating",
        verification_status="pending",
    )

    device_a = _create_device(db, f"device-rapid-{user.id}-a", device_type="mobile", os_name="ios", browser="safari")
    device_b = _create_device(db, f"device-rapid-{user.id}-b", device_type="mobile", os_name="android", browser="chrome")
    _link_user_to_device(db, user.id, device_a.id, usage_count=5, first_seen=created_at)
    _link_user_to_device(db, user.id, device_b.id, usage_count=3, first_seen=created_at + timedelta(hours=1))

    ip_record = _create_ip(db, f"192.0.2.{user_index}", country="US", region="NA", suspicious=True)
    _link_user_to_ip(db, user.id, ip_record.id, usage_count=10, first_seen=created_at)

    for field_name, delta_minutes in [("phone", 20), ("email", 40), ("address", 80), ("device", 110)]:
        _create_identity_change(db, user.id, field_name, created_at + timedelta(minutes=delta_minutes))

    _create_behavior_events(db, user.id, created_at + timedelta(hours=2), rng.randint(12, 30), rng, suspicious=True)
    return user


def generate_dataset(db: Session, users: int = 1000, fraud_ratio: float = 0.12, seed: int = 42, reset: bool = True) -> dict[str, int]:
    rng = random.Random(seed)
    if reset:
        db.query(BehaviorEvent).delete()
        db.query(IdentityChange).delete()
        db.query(UserIPAddress).delete()
        db.query(UserDevice).delete()
        db.query(User).delete()
        db.query(IPAddress).delete()
        db.query(Device).delete()
        db.commit()

    now = datetime.utcnow()
    normal_count = max(1, int(users * (1 - min(max(fraud_ratio, 0.0), 0.5))))
    suspicious_count = max(0, users - normal_count)

    for index in range(normal_count):
        _create_normal_user(db, index + 1, rng, now)

    for cluster_index in range(1, max(1, suspicious_count // 10) + 1):
        _create_identity_farm_cluster(db, cluster_index, now, rng)

    bot_count = max(0, suspicious_count // 4)
    for index in range(bot_count):
        _create_bot_user(db, index + 1, now, rng)

    rapid_count = max(0, suspicious_count // 5)
    for index in range(rapid_count):
        _create_rapid_identity_mutation_user(db, index + 1, now, rng)

    db.commit()

    return {
        "users": db.query(User).count(),
        "devices": db.query(Device).count(),
        "ips": db.query(IPAddress).count(),
        "user_devices": db.query(UserDevice).count(),
        "user_ips": db.query(UserIPAddress).count(),
        "behavior_events": db.query(BehaviorEvent).count(),
        "identity_changes": db.query(IdentityChange).count(),
    }
