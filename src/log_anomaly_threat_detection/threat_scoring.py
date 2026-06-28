from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from psycopg.types.json import Jsonb

from log_anomaly_threat_detection.data_loading import project_root
from log_anomaly_threat_detection.database import connect


@dataclass(frozen=True)
class ThreatScoringResult:
    model_version: str
    rows_scored: int
    security_relevant_count: int
    high_or_critical_count: int
    summary_path: Path


def latest_model_version() -> str:
    sql = "SELECT model_version FROM analytics.request_ip_anomaly_scores ORDER BY scored_at DESC LIMIT 1"
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql)
            row = cursor.fetchone()
    if row is None:
        raise ValueError("No anomaly scores found. Run scripts/train_baseline.py first.")
    return str(row[0])


def threat_level(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def score_row(row: dict[str, Any]) -> tuple[float, str, bool, list[str]]:
    score = 0.0
    reasons: list[str] = []

    anomaly_score = float(row["anomaly_score"])
    suspicious_path_count = int(row["suspicious_path_count"])
    error_rate = float(row["error_rate"])
    error_count = int(row["error_count"])
    request_count = int(row["request_count"])
    unique_endpoint_count = int(row["unique_endpoint_count"])
    static_asset_count = int(row.get("static_asset_count", 0))
    off_hours = bool(row["off_hours"])

    score += anomaly_score * 35
    if anomaly_score >= 0.8:
        reasons.append("very high anomaly score")
    elif anomaly_score >= 0.6:
        reasons.append("high anomaly score")

    if suspicious_path_count >= 100:
        score += 30
        reasons.append("large number of suspicious path probes")
    elif suspicious_path_count >= 20:
        score += 22
        reasons.append("repeated suspicious path probes")
    elif suspicious_path_count > 0:
        score += 12
        reasons.append("suspicious path pattern present")

    if error_rate >= 0.5 and error_count >= 10:
        score += 18
        reasons.append("high error rate with repeated failures")
    elif error_rate >= 0.2 and error_count >= 10:
        score += 12
        reasons.append("elevated error rate")
    elif error_count >= 50:
        score += 10
        reasons.append("large number of error responses")

    if request_count >= 500:
        score += 12
        reasons.append("high request burst")
    elif request_count >= 150:
        score += 8
        reasons.append("elevated request volume")

    if unique_endpoint_count >= 100:
        score += 12
        reasons.append("very broad endpoint access pattern")
    elif unique_endpoint_count >= 30:
        score += 8
        reasons.append("broad endpoint access pattern")

    if off_hours and (request_count >= 100 or suspicious_path_count > 0 or error_count >= 10):
        score += 6
        reasons.append("activity occurred during off-hours")

    static_asset_ratio = static_asset_count / request_count if request_count else 0.0
    if static_asset_ratio >= 0.8 and suspicious_path_count == 0 and error_rate < 0.05:
        score -= 18
        reasons.append("mostly static asset traffic")

    score = min(round(score, 4), 100.0)
    score = max(score, 0.0)
    level = threat_level(score)
    is_security_relevant = level in {"medium", "high", "critical"} and bool(reasons)
    if not reasons:
        reasons.append("low-priority statistical anomaly")
    return score, level, is_security_relevant, reasons


def load_anomaly_context(model_version: str) -> list[dict[str, Any]]:
    sql = """
        SELECT
            s.window_start,
            s.ip_hash,
            s.model_version,
            s.anomaly_score,
            s.anomaly_rank,
            f.request_count,
            f.suspicious_path_count,
            f.error_count,
            f.error_rate,
            f.unique_endpoint_count,
            f.static_asset_count,
            f.off_hours
        FROM analytics.request_ip_anomaly_scores s
        JOIN analytics.request_ip_window_features f
          ON f.window_start = s.window_start
         AND f.ip_hash = s.ip_hash
        WHERE s.model_version = %s
        ORDER BY s.anomaly_rank
    """
    columns = [
        "window_start",
        "ip_hash",
        "model_version",
        "anomaly_score",
        "anomaly_rank",
        "request_count",
        "suspicious_path_count",
        "error_count",
        "error_rate",
        "unique_endpoint_count",
        "static_asset_count",
        "off_hours",
    ]
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, (model_version,))
            return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]


def save_threat_scores(rows: list[dict[str, Any]]) -> None:
    sql = """
        INSERT INTO analytics.request_ip_threat_scores (
            window_start,
            ip_hash,
            model_version,
            threat_score,
            threat_level,
            is_security_relevant,
            reasons,
            anomaly_score,
            anomaly_rank,
            request_count,
            suspicious_path_count,
            error_count,
            error_rate,
            unique_endpoint_count,
            static_asset_count,
            off_hours,
            scored_at
        )
        VALUES (
            %(window_start)s,
            %(ip_hash)s,
            %(model_version)s,
            %(threat_score)s,
            %(threat_level)s,
            %(is_security_relevant)s,
            %(reasons)s,
            %(anomaly_score)s,
            %(anomaly_rank)s,
            %(request_count)s,
            %(suspicious_path_count)s,
            %(error_count)s,
            %(error_rate)s,
            %(unique_endpoint_count)s,
            %(static_asset_count)s,
            %(off_hours)s,
            now()
        )
        ON CONFLICT (window_start, ip_hash, model_version) DO UPDATE SET
            threat_score = EXCLUDED.threat_score,
            threat_level = EXCLUDED.threat_level,
            is_security_relevant = EXCLUDED.is_security_relevant,
            reasons = EXCLUDED.reasons,
            anomaly_score = EXCLUDED.anomaly_score,
            anomaly_rank = EXCLUDED.anomaly_rank,
            request_count = EXCLUDED.request_count,
            suspicious_path_count = EXCLUDED.suspicious_path_count,
            error_count = EXCLUDED.error_count,
            error_rate = EXCLUDED.error_rate,
            unique_endpoint_count = EXCLUDED.unique_endpoint_count,
            static_asset_count = EXCLUDED.static_asset_count,
            off_hours = EXCLUDED.off_hours,
            scored_at = now()
    """
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.executemany(sql, rows)
        conn.commit()


def build_scored_rows(context_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scored_rows = []
    for row in context_rows:
        score, level, is_relevant, reasons = score_row(row)
        scored_rows.append({
            **row,
            "threat_score": score,
            "threat_level": level,
            "is_security_relevant": is_relevant,
            "reasons": Jsonb(reasons),
        })
    return scored_rows


def top_threat_rows(model_version: str, limit: int = 20) -> list[dict[str, Any]]:
    sql = """
        SELECT
            threat_score,
            threat_level,
            is_security_relevant,
            reasons,
            anomaly_score,
            anomaly_rank,
            request_count,
            suspicious_path_count,
            error_rate,
            unique_endpoint_count,
            static_asset_count,
            off_hours,
            window_start,
            ip_hash
        FROM analytics.request_ip_threat_scores
        WHERE model_version = %s
        ORDER BY threat_score DESC, anomaly_score DESC
        LIMIT %s
    """
    columns = [
        "threat_score",
        "threat_level",
        "is_security_relevant",
        "reasons",
        "anomaly_score",
        "anomaly_rank",
        "request_count",
        "suspicious_path_count",
        "error_rate",
        "unique_endpoint_count",
        "static_asset_count",
        "off_hours",
        "window_start",
        "ip_hash",
    ]
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, (model_version, limit))
            return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]


def threat_level_counts(model_version: str) -> dict[str, int]:
    sql = """
        SELECT threat_level, count(*)
        FROM analytics.request_ip_threat_scores
        WHERE model_version = %s
        GROUP BY threat_level
    """
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, (model_version,))
            return {str(level): int(count) for level, count in cursor.fetchall()}


def write_threat_summary(result: ThreatScoringResult, top_rows: list[dict[str, Any]]) -> None:
    counts = threat_level_counts(result.model_version)
    lines = [
        "# Threat Scoring Summary",
        "",
        f"- Model version: `{result.model_version}`",
        f"- Source table: `analytics.request_ip_anomaly_scores`",
        f"- Output table: `analytics.request_ip_threat_scores`",
        f"- Rows scored: {result.rows_scored:,}",
        f"- Security-relevant rows: {result.security_relevant_count:,}",
        f"- High or critical rows: {result.high_or_critical_count:,}",
        "",
        "## Threat Level Counts",
        "",
        "| Level | Count |",
        "| --- | ---: |",
    ]
    for level in ["critical", "high", "medium", "low"]:
        lines.append(f"| {level} | {counts.get(level, 0):,} |")

    lines.extend([
        "",
        "## Top Threat-Scored Windows",
        "",
        "| Threat score | Level | Anomaly score | Request count | Suspicious paths | Error rate | Unique endpoints | Reasons |",
        "| ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ])
    for row in top_rows:
        reasons = ", ".join(row["reasons"])
        lines.append(
            f"| {row['threat_score']:.2f} | {row['threat_level']} | {row['anomaly_score']:.4f} | "
            f"{row['request_count']} | {row['suspicious_path_count']} | {row['error_rate']:.4f} | "
            f"{row['unique_endpoint_count']} | {reasons} |"
        )
    result.summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def score_threats(model_version: str | None = None) -> ThreatScoringResult:
    selected_model_version = model_version or latest_model_version()
    context_rows = load_anomaly_context(selected_model_version)
    if not context_rows:
        raise ValueError(f"No anomaly context rows found for model version {selected_model_version}.")

    scored_rows = build_scored_rows(context_rows)
    save_threat_scores(scored_rows)

    security_relevant_count = sum(1 for row in scored_rows if row["is_security_relevant"])
    high_or_critical_count = sum(1 for row in scored_rows if row["threat_level"] in {"high", "critical"})
    result = ThreatScoringResult(
        model_version=selected_model_version,
        rows_scored=len(scored_rows),
        security_relevant_count=security_relevant_count,
        high_or_critical_count=high_or_critical_count,
        summary_path=project_root() / "reports/summaries/threat_scoring_summary.md",
    )
    write_threat_summary(result, top_threat_rows(selected_model_version, limit=20))
    return result
