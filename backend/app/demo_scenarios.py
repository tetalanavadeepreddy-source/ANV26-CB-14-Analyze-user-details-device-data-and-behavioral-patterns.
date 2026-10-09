from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.data_generation import (
    _create_behavior_events,
    _create_device,
    _create_identity_change,
    _create_ip,
    _hash_value,
    _create_user_record,
    _link_user_to_device,
    _link_user_to_ip,
)
from app.models import BehaviorEvent, Device, IPAddress, User, UserDevice, UserIPAddress

SCENARIOS = {
    "normal-user": "Normal User",
    "shared-wifi": "Shared Wi-Fi",
    "identity-farm": "Identity Farm",
    "device-reuse": "Shared Device",
    "bot-behaviour": "Bot Behaviour",
    "rapid-identity-changes": "Rapid Identity Changes",
    "coordinated-accounts": "Coordinated Accounts",
    "device-farm": "Device Farm",
    "account-creation-burst": "Account Creation Burst",
}


def generate_demo_scenario(db: Session, scenario: str) -> dict[str, object]:
    if scenario not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario}")

    rng = random.Random()
    token = uuid.uuid4().hex[:10]
    now = datetime.utcnow()
    users: list[User] = []

    def mark_suspicious_network(ip_record: IPAddress) -> None:
        ip_record.vpn_detected = True
        ip_record.proxy_detected = True
        ip_record.tor_detected = True
        ip_record.reputation_score = 0.15

    def make_user(index: int, created_at: datetime, suspicious: bool) -> User:
        user = _create_user_record(
            db,
            username=f"demo_{scenario.replace('-', '_')}_{token}_{index}",
            email=f"demo-{scenario}-{token}-{index}@example.com",
            created_at=created_at,
            risk_level="LOW",
            status="active",
            verification_status="pending" if suspicious else "verified",
        )
        users.append(user)
        return user

    if scenario == "normal-user":
        user = make_user(1, now - timedelta(days=90), False)
        device = _create_device(db, f"demo-{token}-desktop")
        ip_record = _create_ip(db, f"demo-{token}-network", suspicious=False)
        _link_user_to_device(db, user.id, device.id, usage_count=18, first_seen=user.created_at)
        _link_user_to_ip(db, user.id, ip_record.id, usage_count=22, first_seen=user.created_at)
        _create_behavior_events(db, user.id, now - timedelta(days=3), 32, rng)

    elif scenario in {"shared-wifi", "device-reuse", "coordinated-accounts"}:
        user_count = 4 if scenario == "shared-wifi" else 8 if scenario == "device-reuse" else 6
        shared_device = _create_device(db, f"demo-{token}-shared-device") if scenario == "device-reuse" or scenario == "coordinated-accounts" else None
        shared_ip = _create_ip(db, f"demo-{token}-shared-network", suspicious=scenario == "coordinated-accounts")
        for index in range(user_count):
            suspicious = scenario == "coordinated-accounts"
            created_at = now - timedelta(minutes=5 * index) if suspicious else now - timedelta(days=45 + index)
            user = make_user(index + 1, created_at, suspicious)
            if suspicious:
                user.phone_hash = _hash_value(f"demo-{token}-coordinated-phone")
                user.address_hash = _hash_value(f"demo-{token}-coordinated-address")
                mark_suspicious_network(shared_ip)
            device = shared_device or _create_device(db, f"demo-{token}-wifi-device-{index}")
            _link_user_to_device(db, user.id, device.id, usage_count=12 + index, first_seen=created_at)
            _link_user_to_ip(db, user.id, shared_ip.id, usage_count=20 + index, first_seen=created_at)
            _create_behavior_events(
                db,
                user.id,
                now - timedelta(days=2) if not suspicious else now - timedelta(minutes=35),
                24 if not suspicious else 30,
                rng,
                suspicious=suspicious,
            )
            if suspicious:
                _create_identity_change(db, user.id, "email", now - timedelta(minutes=25 - index))

    elif scenario == "identity-farm":
        shared_devices = [_create_device(db, f"demo-{token}-farm-device-{index}") for index in range(2)]
        shared_ips = [_create_ip(db, f"demo-{token}-farm-network-{index}", suspicious=True) for index in range(2)]
        for ip_record in shared_ips:
            mark_suspicious_network(ip_record)
        for index in range(8):
            created_at = now - timedelta(minutes=5 * index)
            user = make_user(index + 1, created_at, True)
            user.phone_hash = _hash_value(f"demo-{token}-farm-phone")
            user.address_hash = _hash_value(f"demo-{token}-farm-address")
            for device in shared_devices:
                _link_user_to_device(db, user.id, device.id, usage_count=8 + index, first_seen=created_at)
            for ip_record in shared_ips:
                _link_user_to_ip(db, user.id, ip_record.id, usage_count=5 + index, first_seen=created_at)
            _create_behavior_events(db, user.id, created_at + timedelta(minutes=2), 24, rng, suspicious=True)
            _create_identity_change(db, user.id, "email", now - timedelta(minutes=30 - index))
            _create_identity_change(db, user.id, "phone", now - timedelta(minutes=20 - index))

    elif scenario == "bot-behaviour":
        user = make_user(1, now - timedelta(days=14), True)
        device = _create_device(db, f"demo-{token}-bot-device", os_name="linux")
        ip_record = _create_ip(db, f"demo-{token}-bot-network", suspicious=True)
        mark_suspicious_network(ip_record)
        _link_user_to_device(db, user.id, device.id, usage_count=200, first_seen=user.created_at)
        _link_user_to_ip(db, user.id, ip_record.id, usage_count=150, first_seen=user.created_at)
        for index in range(120):
            db.add(
                BehaviorEvent(
                    user_id=user.id,
                    session_id=f"demo-bot-{token}",
                    event_type="PAGE_VIEW" if index % 4 else "SEARCH",
                    timestamp=now - timedelta(seconds=60) + timedelta(seconds=index * 0.5),
                    duration=0.2,
                    event_metadata='{"source":"demo-scenario","pattern":"bot"}',
                )
            )

    elif scenario == "rapid-identity-changes":
        user = make_user(1, now - timedelta(days=15), True)
        device = _create_device(db, f"demo-{token}-rapid-device")
        ip_record = _create_ip(db, f"demo-{token}-rapid-network", suspicious=True)
        mark_suspicious_network(ip_record)
        _link_user_to_device(db, user.id, device.id, usage_count=11, first_seen=user.created_at)
        _link_user_to_ip(db, user.id, ip_record.id, usage_count=9, first_seen=user.created_at)
        for field, minutes in [("phone", 50), ("email", 35), ("address", 20), ("device", 8)]:
            _create_identity_change(db, user.id, field, now - timedelta(minutes=minutes))
        _create_behavior_events(db, user.id, now - timedelta(hours=2), 24, rng, suspicious=True)

    elif scenario == "device-farm":
        shared_device = _create_device(db, f"demo-{token}-farm-device", os_name="linux")
        shared_ip = _create_ip(db, f"demo-{token}-farm-network", suspicious=True)
        mark_suspicious_network(shared_ip)
        for index in range(10):
            created_at = now - timedelta(minutes=index * 2)
            user = make_user(index + 1, created_at, True)
            _link_user_to_device(db, user.id, shared_device.id, usage_count=20 + index, first_seen=created_at)
            _link_user_to_ip(db, user.id, shared_ip.id, usage_count=15 + index, first_seen=created_at)
            _create_behavior_events(db, user.id, now - timedelta(minutes=20), 24, rng, suspicious=True)
            _create_identity_change(db, user.id, "phone", now - timedelta(minutes=15 - index % 10))

    elif scenario == "account-creation-burst":
        shared_device = _create_device(db, f"demo-{token}-burst-device", os_name="linux")
        shared_ip = _create_ip(db, f"demo-{token}-burst-network", suspicious=True)
        mark_suspicious_network(shared_ip)
        for index in range(12):
            created_at = now - timedelta(minutes=index * 2)
            user = make_user(index + 1, created_at, True)
            _link_user_to_device(db, user.id, shared_device.id, usage_count=2, first_seen=created_at)
            _link_user_to_ip(db, user.id, shared_ip.id, usage_count=8, first_seen=created_at)
            _create_behavior_events(db, user.id, now - timedelta(minutes=10), 18, rng, suspicious=True)

    db.commit()
    return {
        "scenario": scenario,
        "label": SCENARIOS[scenario],
        "user_ids": [user.id for user in users],
        "users": len(users),
        "devices": db.query(Device).count(),
        "ips": db.query(IPAddress).count(),
        "user_devices": db.query(UserDevice).count(),
        "user_ips": db.query(UserIPAddress).count(),
        "behavior_events": db.query(BehaviorEvent).filter(BehaviorEvent.user_id.in_([user.id for user in users])).count(),
    }