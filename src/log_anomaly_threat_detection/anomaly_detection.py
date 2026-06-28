from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
import pickle

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from log_anomaly_threat_detection.data_loading import project_root
from log_anomaly_threat_detection.database import connect


REQUEST_FEATURE_COLUMNS = [
    "request_count",
    "unique_endpoint_count",
    "unique_endpoint_group_count",
    "unique_method_count",
    "unique_user_agent_category_count",
    "static_asset_count",
    "suspicious_path_count",
    "sensitive_query_count",
    "status_2xx_count",
    "status_3xx_count",
    "status_4xx_count",
    "status_5xx_count",
    "error_count",
    "error_rate",
    "avg_latency_ms",
    "p95_latency_ms",
    "max_latency_ms",
    "avg_response_size",
    "avg_endpoint_rarity",
    "off_hours",
]


@dataclass(frozen=True)
class BaselineModelResult:
    model_version: str
    row_count: int
    anomaly_count: int
    anomaly_rate: float
    model_path: Path
    summary_path: Path


def load_request_feature_frame() -> pd.DataFrame:
    columns = ["window_start", "ip_hash", *REQUEST_FEATURE_COLUMNS]
    sql = f"""
        SELECT {", ".join(columns)}
        FROM analytics.request_ip_window_features
        ORDER BY window_start, ip_hash
    """
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql)
            rows = cursor.fetchall()
    return pd.DataFrame(rows, columns=columns)


def build_isolation_forest_pipeline(random_state: int = 42, contamination: str | float = "auto") -> Pipeline:
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        (
            "model",
            IsolationForest(
                n_estimators=200,
                contamination=contamination,
                random_state=random_state,
                n_jobs=-1,
            ),
        ),
    ])


def normalize_anomaly_scores(raw_decision_scores: np.ndarray) -> np.ndarray:
    # IsolationForest decision_function is higher for normal points.
    inverted = -raw_decision_scores
    min_value = float(np.min(inverted))
    max_value = float(np.max(inverted))
    if max_value == min_value:
        return np.zeros_like(inverted, dtype=float)
    return (inverted - min_value) / (max_value - min_value)


def score_request_features(
    frame: pd.DataFrame,
    random_state: int = 42,
    contamination: str | float = "auto",
) -> tuple[Pipeline, pd.DataFrame]:
    if frame.empty:
        raise ValueError("No request IP-window feature rows found. Run scripts/build_features.py first.")

    model_frame = frame[REQUEST_FEATURE_COLUMNS].copy()
    model_frame["off_hours"] = model_frame["off_hours"].astype(int)

    pipeline = build_isolation_forest_pipeline(random_state=random_state, contamination=contamination)
    pipeline.fit(model_frame)

    raw_decision_scores = pipeline.decision_function(model_frame)
    predictions = pipeline.predict(model_frame)
    anomaly_scores = normalize_anomaly_scores(raw_decision_scores)

    scored = frame[["window_start", "ip_hash"]].copy()
    scored["raw_decision_score"] = raw_decision_scores
    scored["anomaly_score"] = anomaly_scores
    scored["is_anomaly"] = predictions == -1
    scored["anomaly_rank"] = scored["anomaly_score"].rank(method="first", ascending=False).astype(int)
    return pipeline, scored


def save_scores(scored: pd.DataFrame, model_version: str, model_name: str = "IsolationForest") -> None:
    sql = """
        INSERT INTO analytics.request_ip_anomaly_scores (
            window_start,
            ip_hash,
            model_name,
            model_version,
            anomaly_score,
            raw_decision_score,
            is_anomaly,
            anomaly_rank,
            scored_at
        )
        VALUES (
            %(window_start)s,
            %(ip_hash)s,
            %(model_name)s,
            %(model_version)s,
            %(anomaly_score)s,
            %(raw_decision_score)s,
            %(is_anomaly)s,
            %(anomaly_rank)s,
            now()
        )
        ON CONFLICT (window_start, ip_hash, model_version) DO UPDATE SET
            model_name = EXCLUDED.model_name,
            anomaly_score = EXCLUDED.anomaly_score,
            raw_decision_score = EXCLUDED.raw_decision_score,
            is_anomaly = EXCLUDED.is_anomaly,
            anomaly_rank = EXCLUDED.anomaly_rank,
            scored_at = now()
    """
    rows = []
    for row in scored.itertuples(index=False):
        rows.append({
            "window_start": row.window_start.to_pydatetime() if hasattr(row.window_start, "to_pydatetime") else row.window_start,
            "ip_hash": row.ip_hash,
            "model_name": model_name,
            "model_version": model_version,
            "anomaly_score": float(row.anomaly_score),
            "raw_decision_score": float(row.raw_decision_score),
            "is_anomaly": bool(row.is_anomaly),
            "anomaly_rank": int(row.anomaly_rank),
        })

    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.executemany(sql, rows)
        conn.commit()


def save_model_artifact(pipeline: Pipeline, model_version: str, metadata: dict[str, Any]) -> Path:
    output_dir = project_root() / "models"
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{model_version}.pkl"
    with path.open("wb") as handle:
        pickle.dump({
            "pipeline": pipeline,
            "feature_columns": REQUEST_FEATURE_COLUMNS,
            "metadata": metadata,
        }, handle)
    return path


def write_baseline_summary(result: BaselineModelResult, top_rows: pd.DataFrame) -> Path:
    path = result.summary_path
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Baseline Model Summary",
        "",
        f"- Model: IsolationForest",
        f"- Model version: `{result.model_version}`",
        f"- Feature table: `analytics.request_ip_window_features`",
        f"- Score table: `analytics.request_ip_anomaly_scores`",
        f"- Feature rows scored: {result.row_count:,}",
        f"- Predicted anomaly rows: {result.anomaly_count:,}",
        f"- Predicted anomaly rate: {result.anomaly_rate:.4f}",
        f"- Model artifact: `{result.model_path.relative_to(project_root())}`",
        "",
        "## Top Scored Windows",
        "",
        "| Rank | Window start | IP hash | Anomaly score | Request count | Suspicious paths | Error rate | Unique endpoints |",
        "| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in top_rows.itertuples(index=False):
        lines.append(
            f"| {row.anomaly_rank} | {row.window_start} | `{row.ip_hash}` | "
            f"{row.anomaly_score:.4f} | {row.request_count} | {row.suspicious_path_count} | "
            f"{row.error_rate:.4f} | {row.unique_endpoint_count} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def top_scored_windows(model_version: str, limit: int = 20) -> pd.DataFrame:
    sql = """
        SELECT
            s.anomaly_rank,
            s.window_start,
            s.ip_hash,
            s.anomaly_score,
            f.request_count,
            f.suspicious_path_count,
            f.error_rate,
            f.unique_endpoint_count
        FROM analytics.request_ip_anomaly_scores s
        JOIN analytics.request_ip_window_features f
          ON f.window_start = s.window_start
         AND f.ip_hash = s.ip_hash
        WHERE s.model_version = %s
        ORDER BY s.anomaly_rank ASC
        LIMIT %s
    """
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, (model_version, limit))
            rows = cursor.fetchall()
    return pd.DataFrame(
        rows,
        columns=[
            "anomaly_rank",
            "window_start",
            "ip_hash",
            "anomaly_score",
            "request_count",
            "suspicious_path_count",
            "error_rate",
            "unique_endpoint_count",
        ],
    )


def train_request_isolation_forest(
    random_state: int = 42,
    contamination: str | float = "auto",
) -> BaselineModelResult:
    model_version = datetime.now(UTC).strftime("request_iforest_%Y%m%d_%H%M%S")
    frame = load_request_feature_frame()
    pipeline, scored = score_request_features(frame, random_state=random_state, contamination=contamination)

    anomaly_count = int(scored["is_anomaly"].sum())
    anomaly_rate = anomaly_count / len(scored)
    metadata = {
        "model_name": "IsolationForest",
        "model_version": model_version,
        "random_state": random_state,
        "contamination": contamination,
        "row_count": len(scored),
        "anomaly_count": anomaly_count,
        "anomaly_rate": anomaly_rate,
        "trained_at_utc": datetime.now(UTC).isoformat(),
    }
    model_path = save_model_artifact(pipeline, model_version, metadata)
    save_scores(scored, model_version)

    result = BaselineModelResult(
        model_version=model_version,
        row_count=len(scored),
        anomaly_count=anomaly_count,
        anomaly_rate=anomaly_rate,
        model_path=model_path,
        summary_path=project_root() / "reports/summaries/baseline_model_summary.md",
    )
    write_baseline_summary(result, top_scored_windows(model_version, limit=20))
    return result
