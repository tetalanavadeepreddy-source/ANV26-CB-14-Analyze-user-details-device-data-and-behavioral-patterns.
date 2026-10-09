from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.data_generation import generate_dataset
from app.database import Base, SessionLocal, engine
from app.features.feature_engineering import export_feature_dataset


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate realistic synthetic IdentityGuard-X data")
    parser.add_argument("--users", type=int, default=500, help="Number of users to generate")
    parser.add_argument("--fraud-ratio", type=float, default=0.12, help="Fraction of users to generate as suspicious")
    parser.add_argument("--seed", type=int, default=42, help="Random seed used for deterministic generation")
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        counts = generate_dataset(session, users=args.users, fraud_ratio=args.fraud_ratio, seed=args.seed, reset=True)

    csv_output = export_feature_dataset(REPO_ROOT / "ml" / "data" / "training_features.csv")
    print(f"Generated dataset: {counts}")
    print(f"Feature export: {csv_output}")


if __name__ == "__main__":
    main()
