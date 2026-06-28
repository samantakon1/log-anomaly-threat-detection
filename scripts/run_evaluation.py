from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from log_anomaly_threat_detection.database import apply_schema
from log_anomaly_threat_detection.evaluation import run_synthetic_evaluation


def main() -> None:
    parser = argparse.ArgumentParser(description="Run synthetic attack-like scenario evaluation.")
    parser.add_argument("--model-version", default=None, help="Model version to evaluate. Defaults to the latest model.")
    parser.add_argument("--rows-per-scenario", type=int, default=100)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    apply_schema()
    result = run_synthetic_evaluation(
        model_version=args.model_version,
        rows_per_scenario=args.rows_per_scenario,
        random_state=args.random_state,
    )

    print(f"Evaluation ID: {result.evaluation_id}")
    print(f"Model version: {result.model_version}")
    print(f"Rows evaluated: {result.rows_evaluated:,}")
    print(f"Attack-like rows: {result.attack_like_rows:,}")
    print(f"Benign anomaly rows: {result.benign_rows:,}")
    print(f"Summary report: {result.summary_path}")


if __name__ == "__main__":
    main()
