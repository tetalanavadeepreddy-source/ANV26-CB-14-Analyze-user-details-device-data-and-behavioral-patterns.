from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
load_dotenv(REPO_ROOT / ".env")

from app.database import SessionLocal
from app.ml_pipeline import FEATURE_NAMES
from app.models import InvestigatorFeedback


def main() -> None:
    parser = argparse.ArgumentParser(description="Export numeric investigator feedback for deliberate offline model retraining")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "ml" / "data" / "investigator_feedback.csv")
    arguments = parser.parse_args()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)

    with SessionLocal() as session, arguments.output.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=[*FEATURE_NAMES, "actual_label"])
        writer.writeheader()
        feedback_rows = session.query(InvestigatorFeedback).order_by(InvestigatorFeedback.created_at.asc()).all()
        for feedback in feedback_rows:
            features = json.loads(feedback.features)
            writer.writerow({**{name: features[name] for name in FEATURE_NAMES}, "actual_label": feedback.actual_label})
    print(f"Exported {len(feedback_rows)} numeric labels to {arguments.output}")


if __name__ == "__main__":
    main()