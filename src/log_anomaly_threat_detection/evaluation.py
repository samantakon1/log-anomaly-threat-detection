from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
import pickle

import pandas as pd
from psycopg.types.json import Jsonb

from log_anomaly_threat_detection.anomaly_detection import (
    REQUEST_FEATURE_COLUMNS,
    load_request_feature_frame,
    normalize_anomaly_scores,
)
from log_anomaly_threat_detection.data_loading import project_root
from log_anomaly_threat_detection.database import connect
from log_anomaly_threat_detection.synthetic_scenarios import generate_synthetic_scenarios
from log_anomaly_threat_detection.threat_scoring import latest_model_version, score_row


@dataclass(frozen=True)
class EvaluationResult:
    evaluation_id: str
    model_version: str
    rows_evaluated: int
    attack_like_rows: int
    benign_rows: int
    summary_path: Path


def load_model_artifact(model_version: str) -> dict[str, Any]:
    path = project_root() / "models" / f"{model_version}.pkl"
    if not path.exists():
        raise FileNotFoundError(f"Model artifact not found: {path}")
    with path.open("rb") as handle:
        return pickle.load(handle)


def score_synthetic_rows(synthetic: pd.DataFrame, model_version: str) -> pd.DataFrame:
    artifact = load_model_artifact(model_version)
    pipeline = artifact["pipeline"]

    real_features = load_request_feature_frame()[REQUEST_FEATURE_COLUMNS].copy()
    synthetic_features = synthetic[REQUEST_FEATURE_COLUMNS].copy()
    combined_features = pd.concat([real_features, synthetic_features], ignore_index=True)
    combined_features["off_hours"] = combined_features["off_hours"].astype(int)

    raw_scores = pipeline.decision_function(combined_features)
    predictions = pipeline.predict(combined_features)
    normalized_scores = normalize_anomaly_scores(raw_scores)
    synthetic_start = len(real_features)

    scored = synthetic.copy()
    scored["raw_decision_score"] = raw_scores[synthetic_start:]
    scored["anomaly_score"] = normalized_scores[synthetic_start:]
    scored["is_anomaly"] = predictions[synthetic_start:] == -1
    scored["anomaly_rank"] = scored["anomaly_score"].rank(method="first", ascending=False).astype(int)

    threat_scores = []
    threat_levels = []
    is_security_relevant = []
    reasons = []
    for row in scored.to_dict(orient="records"):
        threat_score, threat_level, relevant, row_reasons = score_row(row)
        threat_scores.append(threat_score)
        threat_levels.append(threat_level)
        is_security_relevant.append(relevant)
        reasons.append(row_reasons)

    scored["threat_score"] = threat_scores
    scored["threat_level"] = threat_levels
    scored["is_security_relevant"] = is_security_relevant
    scored["reasons"] = reasons
    scored["threat_rank"] = scored["threat_score"].rank(method="first", ascending=False).astype(int)
    return scored


def precision_at_k(scored: pd.DataFrame, score_column: str, k: int) -> float:
    top = scored.sort_values(score_column, ascending=False).head(k)
    if top.empty:
        return 0.0
    return float(top["is_attack_like"].mean())


def recall_at_k(scored: pd.DataFrame, score_column: str, k: int) -> float:
    attack_total = int(scored["is_attack_like"].sum())
    if attack_total == 0:
        return 0.0
    top = scored.sort_values(score_column, ascending=False).head(k)
    return float(top["is_attack_like"].sum() / attack_total)


def evaluation_metrics(scored: pd.DataFrame, evaluation_id: str, model_version: str) -> list[dict[str, Any]]:
    rows = []
    for ranking_method, score_column in [
        ("anomaly_only", "anomaly_score"),
        ("anomaly_plus_threat_score", "threat_score"),
    ]:
        for k in [10, 20, 50, 100, 200, 300]:
            rows.append({
                "evaluation_id": evaluation_id,
                "model_version": model_version,
                "ranking_method": ranking_method,
                "metric_name": "precision_at_k",
                "k_value": k,
                "metric_value": precision_at_k(scored, score_column, k),
            })
            rows.append({
                "evaluation_id": evaluation_id,
                "model_version": model_version,
                "ranking_method": ranking_method,
                "metric_name": "recall_at_k",
                "k_value": k,
                "metric_value": recall_at_k(scored, score_column, k),
            })

    rows.extend(classification_metrics(scored, evaluation_id, model_version, "anomaly_only_flag", "is_anomaly"))
    rows.extend(classification_metrics(scored, evaluation_id, model_version, "threat_score_flag", "is_security_relevant"))
    return rows


def classification_metrics(
    scored: pd.DataFrame,
    evaluation_id: str,
    model_version: str,
    ranking_method: str,
    prediction_column: str,
) -> list[dict[str, Any]]:
    predicted = scored[prediction_column].astype(bool)
    actual = scored["is_attack_like"].astype(bool)

    true_positive = int((predicted & actual).sum())
    false_positive = int((predicted & ~actual).sum())
    false_negative = int((~predicted & actual).sum())
    true_negative = int((~predicted & ~actual).sum())

    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    false_positive_rate = false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0

    values = {
        "precision": precision,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "predicted_positive_count": float(true_positive + false_positive),
        "false_positive_count": float(false_positive),
    }
    return [
        {
            "evaluation_id": evaluation_id,
            "model_version": model_version,
            "ranking_method": ranking_method,
            "metric_name": metric_name,
            "k_value": 0,
            "metric_value": metric_value,
        }
        for metric_name, metric_value in values.items()
    ]


def save_synthetic_scores(evaluation_id: str, model_version: str, scored: pd.DataFrame) -> None:
    sql = """
        INSERT INTO analytics.synthetic_scenario_scores (
            evaluation_id,
            synthetic_id,
            scenario_name,
            is_attack_like,
            model_version,
            anomaly_score,
            is_anomaly,
            threat_score,
            threat_level,
            is_security_relevant,
            anomaly_rank,
            threat_rank,
            reasons,
            request_count,
            suspicious_path_count,
            error_count,
            error_rate,
            unique_endpoint_count,
            static_asset_count,
            off_hours,
            created_at
        )
        VALUES (
            %(evaluation_id)s,
            %(synthetic_id)s,
            %(scenario_name)s,
            %(is_attack_like)s,
            %(model_version)s,
            %(anomaly_score)s,
            %(is_anomaly)s,
            %(threat_score)s,
            %(threat_level)s,
            %(is_security_relevant)s,
            %(anomaly_rank)s,
            %(threat_rank)s,
            %(reasons)s,
            %(request_count)s,
            %(suspicious_path_count)s,
            %(error_count)s,
            %(error_rate)s,
            %(unique_endpoint_count)s,
            %(static_asset_count)s,
            %(off_hours)s,
            now()
        )
        ON CONFLICT (evaluation_id, synthetic_id) DO UPDATE SET
            anomaly_score = EXCLUDED.anomaly_score,
            is_anomaly = EXCLUDED.is_anomaly,
            threat_score = EXCLUDED.threat_score,
            threat_level = EXCLUDED.threat_level,
            is_security_relevant = EXCLUDED.is_security_relevant,
            anomaly_rank = EXCLUDED.anomaly_rank,
            threat_rank = EXCLUDED.threat_rank,
            reasons = EXCLUDED.reasons,
            created_at = now()
    """
    rows = []
    for row in scored.to_dict(orient="records"):
        rows.append({
            "evaluation_id": evaluation_id,
            "synthetic_id": row["synthetic_id"],
            "scenario_name": row["scenario_name"],
            "is_attack_like": bool(row["is_attack_like"]),
            "model_version": model_version,
            "anomaly_score": float(row["anomaly_score"]),
            "is_anomaly": bool(row["is_anomaly"]),
            "threat_score": float(row["threat_score"]),
            "threat_level": row["threat_level"],
            "is_security_relevant": bool(row["is_security_relevant"]),
            "anomaly_rank": int(row["anomaly_rank"]),
            "threat_rank": int(row["threat_rank"]),
            "reasons": Jsonb(row["reasons"]),
            "request_count": int(row["request_count"]),
            "suspicious_path_count": int(row["suspicious_path_count"]),
            "error_count": int(row["error_count"]),
            "error_rate": float(row["error_rate"]),
            "unique_endpoint_count": int(row["unique_endpoint_count"]),
            "static_asset_count": int(row["static_asset_count"]),
            "off_hours": bool(row["off_hours"]),
        })

    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.executemany(sql, rows)
        conn.commit()


def save_metrics(rows: list[dict[str, Any]]) -> None:
    sql = """
        INSERT INTO analytics.synthetic_scenario_metrics (
            evaluation_id,
            model_version,
            ranking_method,
            metric_name,
            k_value,
            metric_value,
            created_at
        )
        VALUES (
            %(evaluation_id)s,
            %(model_version)s,
            %(ranking_method)s,
            %(metric_name)s,
            %(k_value)s,
            %(metric_value)s,
            now()
        )
        ON CONFLICT (evaluation_id, ranking_method, metric_name, k_value) DO UPDATE SET
            metric_value = EXCLUDED.metric_value,
            created_at = now()
    """
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.executemany(sql, rows)
        conn.commit()


def write_evaluation_summary(result: EvaluationResult, scored: pd.DataFrame, metrics: list[dict[str, Any]]) -> None:
    metric_frame = pd.DataFrame(metrics)
    lines = [
        "# Synthetic Scenario Evaluation Summary",
        "",
        f"- Evaluation ID: `{result.evaluation_id}`",
        f"- Model version: `{result.model_version}`",
        f"- Synthetic rows evaluated: {result.rows_evaluated:,}",
        f"- Attack-like rows: {result.attack_like_rows:,}",
        f"- Benign anomaly rows: {result.benign_rows:,}",
        "",
        "## Precision and Recall",
        "",
        "| Ranking method | Metric | K | Value |",
        "| --- | --- | ---: | ---: |",
    ]
    top_k_frame = metric_frame[metric_frame["k_value"] > 0].copy()
    for row in top_k_frame.sort_values(["ranking_method", "metric_name", "k_value"]).to_dict(orient="records"):
        lines.append(
            f"| {row['ranking_method']} | {row['metric_name']} | {row['k_value']} | {row['metric_value']:.4f} |"
        )

    classification_frame = metric_frame[metric_frame["k_value"] == 0].copy()
    lines.extend([
        "",
        "## Classification Metrics",
        "",
        "| Method | Metric | Value |",
        "| --- | --- | ---: |",
    ])
    for row in classification_frame.sort_values(["ranking_method", "metric_name"]).to_dict(orient="records"):
        lines.append(f"| {row['ranking_method']} | {row['metric_name']} | {row['metric_value']:.4f} |")

    scenario_summary = scored.groupby(["scenario_name", "is_attack_like"]).agg(
        rows=("synthetic_id", "count"),
        avg_anomaly_score=("anomaly_score", "mean"),
        avg_threat_score=("threat_score", "mean"),
        security_relevant_rows=("is_security_relevant", "sum"),
    ).reset_index()

    lines.extend([
        "",
        "## Scenario Summary",
        "",
        "| Scenario | Attack-like | Rows | Avg anomaly score | Avg threat score | Security-relevant rows |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ])
    for row in scenario_summary.to_dict(orient="records"):
        lines.append(
            f"| {row['scenario_name']} | {row['is_attack_like']} | {row['rows']} | "
            f"{row['avg_anomaly_score']:.4f} | {row['avg_threat_score']:.2f} | {int(row['security_relevant_rows'])} |"
        )

    result.summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_synthetic_evaluation(
    model_version: str | None = None,
    rows_per_scenario: int = 100,
    random_state: int = 42,
) -> EvaluationResult:
    selected_model_version = model_version or latest_model_version()
    evaluation_id = datetime.now(UTC).strftime("synthetic_eval_%Y%m%d_%H%M%S")
    synthetic = generate_synthetic_scenarios(rows_per_scenario=rows_per_scenario, random_state=random_state)
    scored = score_synthetic_rows(synthetic, selected_model_version)
    metrics = evaluation_metrics(scored, evaluation_id, selected_model_version)

    save_synthetic_scores(evaluation_id, selected_model_version, scored)
    save_metrics(metrics)

    result = EvaluationResult(
        evaluation_id=evaluation_id,
        model_version=selected_model_version,
        rows_evaluated=len(scored),
        attack_like_rows=int(scored["is_attack_like"].sum()),
        benign_rows=int((~scored["is_attack_like"]).sum()),
        summary_path=project_root() / "reports/summaries/evaluation_summary.md",
    )
    write_evaluation_summary(result, scored, metrics)
    return result
