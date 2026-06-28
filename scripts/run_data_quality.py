from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from log_anomaly_threat_detection.data_loading import load_dataset_config, load_jsonl
from log_anomaly_threat_detection.data_quality import (
    format_summary_markdown,
    summarize_app_logs,
    summarize_request_logs,
    write_quality_csv,
)


def main() -> None:
    datasets = load_dataset_config()

    request_config = datasets["request_logs_30d"]
    app_config = datasets["app_logs_7d"]

    request_rows = load_jsonl(request_config["path"])
    app_rows = load_jsonl(app_config["path"])

    request_summary = summarize_request_logs(request_rows, "request_logs_30d")
    app_summary = summarize_app_logs(app_rows, "app_logs_7d")

    reports_dir = PROJECT_ROOT / "reports"
    write_quality_csv(reports_dir / "tables" / "request_log_quality.csv", request_summary)
    write_quality_csv(reports_dir / "tables" / "app_log_quality.csv", app_summary)

    summary_path = reports_dir / "summaries" / "dataset_quality_summary.md"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(format_summary_markdown(request_summary, app_summary), encoding="utf-8")

    print(f"Loaded request rows: {len(request_rows):,}")
    print(f"Loaded app rows: {len(app_rows):,}")
    print(f"Wrote {summary_path}")


if __name__ == "__main__":
    main()
