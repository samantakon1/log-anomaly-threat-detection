from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from log_anomaly_threat_detection.database import apply_schema
from log_anomaly_threat_detection.threat_scoring import score_threats


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply second-stage threat scoring to request IP anomaly scores.")
    parser.add_argument("--model-version", default=None, help="Anomaly model version to score. Defaults to the latest version.")
    args = parser.parse_args()

    apply_schema()
    result = score_threats(model_version=args.model_version)

    print(f"Model version: {result.model_version}")
    print(f"Rows scored: {result.rows_scored:,}")
    print(f"Security-relevant rows: {result.security_relevant_count:,}")
    print(f"High or critical rows: {result.high_or_critical_count:,}")
    print(f"Summary report: {result.summary_path}")


if __name__ == "__main__":
    main()
