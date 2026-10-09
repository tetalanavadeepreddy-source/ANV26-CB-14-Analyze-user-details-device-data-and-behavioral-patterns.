from __future__ import annotations

import csv
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func

from app.database import SessionLocal
from app.models import BehaviorEvent, IdentityChange, IPAddress, User, UserDevice, UserIPAddress


def _safe_average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def build_user_feature_vector(user_id: int, db=None) -> dict[str, Any]:
    provided_db = db
    db = db or SessionLocal()
    close_session = provided_db is None
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError(f"User {user_id} not found")

        now = datetime.utcnow()
        account_age_hours = max((now - user.created_at).total_seconds() / 3600.0, 0.0)
        account_age_days = account_age_hours / 24.0

        identity_changes = (
            db.query(IdentityChange)
            .filter(IdentityChange.user_id == user_id)
            .order_by(IdentityChange.timestamp.asc())
            .all()
        )
        identity_change_count = len(identity_changes)
        identity_changes_last_24h = sum(
            1 for change in identity_changes if now - change.timestamp <= timedelta(hours=24)
        )

        email_domain = user.email.lower().rsplit("@", 1)[-1]
        exact_email_matches = db.query(User).filter(func.lower(User.email) == user.email.lower()).count()
        email_domain_matches = db.query(User).filter(func.lower(User.email).like(f"%@{email_domain}")).count()
        accounts_same_phone = db.query(User).filter(User.phone_hash == user.phone_hash).count() if user.phone_hash else 1
        accounts_same_address = db.query(User).filter(User.address_hash == user.address_hash).count() if user.address_hash else 1

        user_devices = db.query(UserDevice).filter(UserDevice.user_id == user_id).all()
        device_ids = [link.device_id for link in user_devices]
        device_counts = dict(
            db.query(UserDevice.device_id, func.count(UserDevice.user_id))
            .filter(UserDevice.device_id.in_(device_ids))
            .group_by(UserDevice.device_id)
            .all()
        ) if device_ids else {}
        device_account_count = max(device_counts.values(), default=1)
        device_usage_frequency = _safe_average([link.usage_count for link in user_devices])
        device_age_days = _safe_average(
            [max((now - link.device.first_seen).total_seconds() / 86400.0, 0.0) for link in user_devices if link.device]
        )
        device_reuse_score = device_account_count / max(len(device_ids), 1)

        user_ips = db.query(UserIPAddress).filter(UserIPAddress.user_id == user_id).all()
        ip_ids = [link.ip_id for link in user_ips]
        ip_counts = dict(
            db.query(UserIPAddress.ip_id, func.count(UserIPAddress.user_id))
            .filter(UserIPAddress.ip_id.in_(ip_ids))
            .group_by(UserIPAddress.ip_id)
            .all()
        ) if ip_ids else {}
        ip_account_count = max(ip_counts.values(), default=1)
        ip_records = db.query(IPAddress).filter(IPAddress.id.in_(ip_ids)).all() if ip_ids else []
        ip_reputation = _safe_average([ip.reputation_score for ip in ip_records])
        vpn_flag = any(ip.vpn_detected for ip in ip_records)
        proxy_flag = any(ip.proxy_detected for ip in ip_records)
        tor_flag = any(ip.tor_detected for ip in ip_records)
        location_change_frequency = len({ip.country for ip in ip_records})

        events = (
            db.query(BehaviorEvent)
            .filter(BehaviorEvent.user_id == user_id)
            .order_by(BehaviorEvent.timestamp.asc())
            .all()
        )
        session_bounds: dict[str, tuple[datetime, datetime]] = {}
        for event in events:
            if not event.timestamp:
                continue
            bounds = session_bounds.get(event.session_id)
            if bounds:
                session_bounds[event.session_id] = (min(bounds[0], event.timestamp), max(bounds[1], event.timestamp))
            else:
                session_bounds[event.session_id] = (event.timestamp, event.timestamp)
        session_durations = [
            max((last - first).total_seconds(), 0.0)
            for first, last in session_bounds.values()
        ]
        average_session_duration = _safe_average(
            session_durations
        )
        failed_login_count = sum(1 for event in events if event.event_type == "FAILED_LOGIN")
        device_change_count = sum(1 for change in identity_changes if change.field_changed.lower() == "device")
        recent_events = [event for event in events if event.timestamp and now - event.timestamp <= timedelta(hours=24)]
        event_intervals = [
            (recent_events[index].timestamp - recent_events[index - 1].timestamp).total_seconds()
            for index in range(1, len(recent_events))
            if recent_events[index].timestamp >= recent_events[index - 1].timestamp
        ]
        average_action_interval = _safe_average(event_intervals)
        action_interval_std = statistics.pstdev(event_intervals) if len(event_intervals) > 1 else 0.0
        if len(recent_events) > 1:
            elapsed_minutes = max((recent_events[-1].timestamp - recent_events[0].timestamp).total_seconds() / 60.0, 1.0)
            actions_per_minute = len(recent_events) / elapsed_minutes
            request_velocity = len(recent_events) / 24.0
        else:
            actions_per_minute = 0.0
            request_velocity = 0.0
        minute_events = [event for event in recent_events if now - event.timestamp <= timedelta(minutes=1)]
        requests_per_second = len(minute_events) / 60.0
        repeated_actions = sum(
            1 for index in range(1, len(recent_events))
            if recent_events[index].session_id == recent_events[index - 1].session_id
            and recent_events[index].event_type == recent_events[index - 1].event_type
        )
        repeated_action_ratio = repeated_actions / max(len(recent_events) - 1, 1)
        navigation_events = sum(1 for event in recent_events if event.event_type in {"PAGE_VIEW", "SEARCH", "PROFILE_VIEW"})
        navigation_velocity = navigation_events / max((len(recent_events) - 1) / max(actions_per_minute, 1.0), 1.0)
        login_burst_score = sum(1 for event in recent_events if event.event_type == "LOGIN" and now - event.timestamp <= timedelta(hours=1))
        login_velocity = login_burst_score / 60.0

        created_hour = user.created_at.replace(minute=0, second=0, microsecond=0)
        created_day = user.created_at.replace(hour=0, minute=0, second=0, microsecond=0)
        accounts_created_same_hour = db.query(User).filter(User.created_at >= created_hour).filter(User.created_at < created_hour + timedelta(hours=1)).count()
        accounts_created_same_day = db.query(User).filter(User.created_at >= created_day).filter(User.created_at < created_day + timedelta(days=1)).count()
        account_creation_burst = accounts_created_same_day

        if len(identity_changes) > 1:
            change_deltas = [
                (identity_changes[index].timestamp - identity_changes[index - 1].timestamp).total_seconds()
                for index in range(1, len(identity_changes))
                if identity_changes[index].timestamp and identity_changes[index - 1].timestamp
            ]
            time_between_identity_changes = _safe_average(change_deltas)
        else:
            time_between_identity_changes = 0.0

        device_reuse_counts = dict(
            db.query(UserDevice.device_id, func.count(UserDevice.user_id))
            .filter(UserDevice.device_id.in_(device_ids))
            .group_by(UserDevice.device_id)
            .all()
        ) if device_ids else {}
        ip_reuse_counts = dict(
            db.query(UserIPAddress.ip_id, func.count(UserIPAddress.user_id))
            .filter(UserIPAddress.ip_id.in_(ip_ids))
            .group_by(UserIPAddress.ip_id)
            .all()
        ) if ip_ids else {}
        shared_device_count = sum(1 for count in device_reuse_counts.values() if count > 1)
        shared_ip_count = sum(1 for count in ip_reuse_counts.values() if count > 1)

        connected_ids: set[int] = set()
        for device_id in device_ids:
            connected_ids.update(row[0] for row in db.query(UserDevice.user_id).filter(UserDevice.device_id == device_id).all())
        for ip_id in ip_ids:
            connected_ids.update(row[0] for row in db.query(UserIPAddress.user_id).filter(UserIPAddress.ip_id == ip_id).all())
        connected_ids.discard(user_id)
        connected_user_count = len(connected_ids)
        cluster_size = connected_user_count + 1
        related_user_ids = connected_ids | {user_id}
        graph_pairs: set[tuple[int, int]] = set()
        device_owners: dict[int, list[int]] = {}
        ip_owners: dict[int, list[int]] = {}
        for related_user, related_device in db.query(UserDevice.user_id, UserDevice.device_id).filter(UserDevice.user_id.in_(related_user_ids)).all():
            device_owners.setdefault(related_device, []).append(related_user)
        for related_user, related_ip in db.query(UserIPAddress.user_id, UserIPAddress.ip_id).filter(UserIPAddress.user_id.in_(related_user_ids)).all():
            ip_owners.setdefault(related_ip, []).append(related_user)
        for owners in [*device_owners.values(), *ip_owners.values()]:
            graph_pairs.update((min(left, right), max(left, right)) for index, left in enumerate(owners) for right in owners[index + 1:])
        possible_graph_pairs = cluster_size * (cluster_size - 1) / 2
        cluster_density = len(graph_pairs) / possible_graph_pairs if possible_graph_pairs else 0.0
        suspicious_neighbor_count = db.query(User).filter(User.id.in_(connected_ids), User.risk_level.in_(["MEDIUM", "HIGH"])).count() if connected_ids else 0

        return {
            "user_id": user.id,
            "account_age_hours": round(account_age_hours, 2),
            "account_age_days": round(account_age_days, 2),
            "identity_change_count": identity_change_count,
            "identity_changes_last_24h": identity_changes_last_24h,
            "accounts_same_email": max(exact_email_matches - 1, 0),
            "email_exact_reuse_count": max(exact_email_matches - 1, 0),
            "email_domain_reuse_count": max(email_domain_matches - exact_email_matches, 0),
            "accounts_same_phone": accounts_same_phone,
            "phone_reuse_count": accounts_same_phone,
            "accounts_same_address": accounts_same_address,
            "address_reuse_count": accounts_same_address,
            "verification_status": user.identity_verification_status,
            "verification_verified": int(user.identity_verification_status.lower() == "verified"),
            "device_account_count": device_account_count,
            "device_usage_frequency": round(device_usage_frequency, 2),
            "device_reuse_score": round(device_reuse_score, 4),
            "device_age_days": round(device_age_days, 2),
            "devices_per_user": len(device_ids),
            "device_change_frequency": round((device_change_count + max(len(device_ids) - 1, 0)) / max(account_age_days, 1.0), 4),
            "shared_device_count": shared_device_count,
            "device_link_count": len(device_ids),
            "ip_account_count": ip_account_count,
            "ip_user_count": ip_account_count,
            "shared_ip_count": shared_ip_count,
            "ip_link_count": len(ip_ids),
            "vpn_flag": vpn_flag,
            "vpn_indicator": int(vpn_flag),
            "proxy_flag": proxy_flag,
            "proxy_indicator": int(proxy_flag),
            "tor_flag": tor_flag,
            "tor_indicator": int(tor_flag),
            "ip_reputation": round(ip_reputation, 3),
            "ip_reputation_score": round(ip_reputation, 3),
            "ip_reputation_source": "synthetic_test_signal" if ip_records else "not_available",
            "location_change_frequency": location_change_frequency,
            "country_change_frequency": location_change_frequency,
            "average_session_duration": round(average_session_duration, 2),
            "session_duration": round(average_session_duration, 2),
            "device_change_count": device_change_count,
            "identity_changes_24h": identity_changes_last_24h,
            "actions_per_minute": round(actions_per_minute, 2),
            "requests_per_second": round(requests_per_second, 4),
            "average_action_interval": round(average_action_interval, 2),
            "action_interval_std": round(action_interval_std, 2),
            "repeated_action_ratio": round(repeated_action_ratio, 4),
            "navigation_velocity": round(navigation_velocity, 2),
            "login_velocity": round(login_velocity, 4),
            "failed_login_count": failed_login_count,
            "request_velocity": round(request_velocity, 2),
            "account_creation_burst": account_creation_burst,
            "accounts_created_same_hour": accounts_created_same_hour,
            "accounts_created_same_day": accounts_created_same_day,
            "login_burst_score": login_burst_score,
            "time_between_identity_changes": round(time_between_identity_changes, 2),
            "recent_identity_changes": identity_changes_last_24h,
            "connected_user_count": connected_user_count,
            "graph_degree": len(device_ids) + len(ip_ids),
            "cluster_size": cluster_size,
            "cluster_density": round(cluster_density, 4),
            "suspicious_neighbor_count": suspicious_neighbor_count,
            "behavior_event_count": len(events),
        }
    finally:
        if close_session:
            db.close()


def export_feature_dataset(output_path: str | Path | None = None) -> Path:
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.id.asc()).all()
        if output_path is None:
            output_path = Path(__file__).resolve().parents[2] / "ml" / "data" / "training_features.csv"
        else:
            output_path = Path(output_path)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "user_id",
            "account_age_days",
            "identity_change_count",
            "identity_changes_last_24h",
            "accounts_same_email",
            "accounts_same_phone",
            "accounts_same_address",
            "verification_status",
            "device_account_count",
            "device_usage_frequency",
            "device_reuse_score",
            "device_age_days",
            "ip_account_count",
            "vpn_flag",
            "proxy_flag",
            "tor_flag",
            "ip_reputation",
            "location_change_frequency",
            "average_session_duration",
            "device_change_count",
            "actions_per_minute",
            "average_action_interval",
            "failed_login_count",
            "request_velocity",
            "account_creation_burst",
            "login_burst_score",
            "time_between_identity_changes",
            "recent_identity_changes",
            "label",
        ]

        rows = []
        for user in users:
            feature_row = build_user_feature_vector(user.id)
            suspicious_score = (
                feature_row["identity_changes_last_24h"] * 0.65
                + feature_row["failed_login_count"] * 0.5
                + feature_row["account_creation_burst"] * 0.25
                + feature_row["device_account_count"] * 0.1
                + feature_row["ip_account_count"] * 0.1
                + feature_row["actions_per_minute"] * 0.05
            )
            feature_row["label"] = 1 if suspicious_score >= 2.0 or user.risk_level in {"MEDIUM", "HIGH"} else 0
            rows.append({k: feature_row.get(k, "") for k in fieldnames})

        with output_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return output_path
    finally:
        db.close()
