from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from log_anomaly_threat_detection.database import apply_schema
from log_anomaly_threat_detection.feature_engineering import (
    build_app_user_window_features,
    build_request_ip_window_features,
    feature_table_summary,
)


def main() -> None:
    apply_schema()

    request_rows = build_request_ip_window_features()
    app_rows = build_app_user_window_features()
    summary = feature_table_summary()

    print(f"Request IP-window feature rows: {request_rows:,}")
    print(f"Application user-window feature rows: {app_rows:,}")
    print("Feature summary:")
    for key, value in summary.items():
        print(f"- {key}: {value}")


if __name__ == "__main__":
    main()
