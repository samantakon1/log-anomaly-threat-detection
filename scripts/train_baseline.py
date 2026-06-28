from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from log_anomaly_threat_detection.anomaly_detection import train_request_isolation_forest
from log_anomaly_threat_detection.database import apply_schema


def parse_contamination(value: str) -> str | float:
    if value == "auto":
        return value
    parsed = float(value)
    if not 0.0 < parsed <= 0.5:
        raise argparse.ArgumentTypeError("contamination must be 'auto' or a float in (0.0, 0.5].")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the baseline request-log Isolation Forest model.")
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--contamination", type=parse_contamination, default="auto")
    args = parser.parse_args()

    apply_schema()
    result = train_request_isolation_forest(
        random_state=args.random_state,
        contamination=args.contamination,
    )

    print(f"Model version: {result.model_version}")
    print(f"Rows scored: {result.row_count:,}")
    print(f"Predicted anomalies: {result.anomaly_count:,}")
    print(f"Predicted anomaly rate: {result.anomaly_rate:.4f}")
    print(f"Model artifact: {result.model_path}")
    print(f"Summary report: {result.summary_path}")


if __name__ == "__main__":
    main()
