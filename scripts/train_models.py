from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.ml_pipeline import train_models


def main() -> None:
    parser = argparse.ArgumentParser(description="Train IdentityGuard synthetic fraud and anomaly models")
    parser.add_argument("--samples", type=int, default=6000, help="Synthetic records to generate")
    parser.add_argument("--seed", type=int, default=42, help="Reproducible split and model seed")
    parser.add_argument("--feedback-csv", type=Path, help="Optional numeric investigator-feedback CSV exported offline")
    arguments = parser.parse_args()
    metrics = train_models(arguments.samples, arguments.seed, arguments.feedback_csv)
    print(json.dumps(metrics, indent=2))
    print(f"Dataset: {REPO_ROOT / 'ml' / 'data' / 'synthetic_training.csv'}")
    print(f"Models: {BACKEND_ROOT / 'models'}")


if __name__ == "__main__":
    main()