from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from log_anomaly_threat_detection.database import connect
from log_anomaly_threat_detection.threat_scoring import latest_model_version


DEFAULT_ALERT_LIMIT = 50
MAX_ALERT_LIMIT = 200


@dataclass(frozen=True)
class DashboardFilters:
    model_version: str | None = None
    threat_level: str | None = None
    security_relevant: bool | None = None
    ip_hash: str | None = None
    limit: int = DEFAULT_ALERT_LIMIT


def _selected_model_version(model_version: str | None = None) -> str:
    return model_version or latest_model_version()


def _json_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def get_overview(model_version: str | None = None) -> dict[str, Any]:
    selected = _selected_model_version(model_version)
    sql = """
        SELECT
            count(*) AS total_windows,
            count(*) FILTER (WHERE anomaly_score >= 0.6) AS high_anomaly_score_windows,
            count(*) FILTER (WHERE is_security_relevant) AS security_relevant_windows,
            count(*) FILTER (WHERE threat_level IN ('high', 'critical')) AS high_or_critical_windows,
            avg(anomaly_score) AS avg_anomaly_score,
            avg(threat_score) AS avg_threat_score,
            min(window_start) AS first_window,
            max(window_start) AS last_window
        FROM analytics.request_ip_threat_scores
        WHERE model_version = %s
    """
    level_sql = """
        SELECT threat_level, count(*)
        FROM analytics.request_ip_threat_scores
        WHERE model_version = %s
        GROUP BY threat_level
    """
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, (selected,))
            row = cursor.fetchone()
            cursor.execute(level_sql, (selected,))
            levels = {str(level): int(count) for level, count in cursor.fetchall()}

    if row is None:
        raise ValueError(f"No dashboard rows found for model version {selected}.")

    return {
        "model_version": selected,
        "total_windows": int(row[0] or 0),
        "high_anomaly_score_windows": int(row[1] or 0),
        "security_relevant_windows": int(row[2] or 0),
        "high_or_critical_windows": int(row[3] or 0),
        "avg_anomaly_score": float(row[4] or 0.0),
        "avg_threat_score": float(row[5] or 0.0),
        "first_window": row[6],
        "last_window": row[7],
        "threat_level_counts": {level: levels.get(level, 0) for level in ["critical", "high", "medium", "low"]},
    }


def get_alerts(filters: DashboardFilters) -> list[dict[str, Any]]:
    selected = _selected_model_version(filters.model_version)
    limit = max(1, min(filters.limit, MAX_ALERT_LIMIT))

    conditions = ["t.model_version = %(model_version)s"]
    params: dict[str, Any] = {"model_version": selected, "limit": limit}
    if filters.threat_level:
        conditions.append("t.threat_level = %(threat_level)s")
        params["threat_level"] = filters.threat_level
    if filters.security_relevant is not None:
        conditions.append("t.is_security_relevant = %(security_relevant)s")
        params["security_relevant"] = filters.security_relevant
    if filters.ip_hash:
        conditions.append("t.ip_hash = %(ip_hash)s")
        params["ip_hash"] = filters.ip_hash

    sql = f"""
        SELECT
            t.window_start,
            t.ip_hash,
            t.model_version,
            t.threat_score,
            t.threat_level,
            t.is_security_relevant,
            t.reasons,
            t.anomaly_score,
            t.anomaly_rank,
            t.request_count,
            t.suspicious_path_count,
            t.error_count,
            t.error_rate,
            t.unique_endpoint_count,
            t.static_asset_count,
            t.off_hours,
            context.module_id,
            context.endpoint_template,
            context.endpoint_group,
            context.status_family
        FROM analytics.request_ip_threat_scores t
        LEFT JOIN LATERAL (
            SELECT
                r.module_id,
                r.endpoint_template,
                r.endpoint_group,
                r.status_family,
                count(*) AS event_count
            FROM analytics.request_logs r
            WHERE r.ip_hash = t.ip_hash
              AND r.timestamp >= t.window_start
              AND r.timestamp < t.window_start + interval '5 minutes'
            GROUP BY r.module_id, r.endpoint_template, r.endpoint_group, r.status_family
            ORDER BY count(*) DESC, r.endpoint_template ASC
            LIMIT 1
        ) context ON true
        WHERE {" AND ".join(conditions)}
        ORDER BY t.threat_score DESC, t.anomaly_score DESC, t.window_start DESC
        LIMIT %(limit)s
    """
    columns = [
        "window_start",
        "ip_hash",
        "model_version",
        "threat_score",
        "threat_level",
        "is_security_relevant",
        "reasons",
        "anomaly_score",
        "anomaly_rank",
        "request_count",
        "suspicious_path_count",
        "error_count",
        "error_rate",
        "unique_endpoint_count",
        "static_asset_count",
        "off_hours",
        "module_id",
        "endpoint_template",
        "endpoint_group",
        "status_family",
    ]
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, params)
            rows = cursor.fetchall()

    alerts = []
    for row in rows:
        item = dict(zip(columns, row, strict=True))
        item["reasons"] = _json_list(item["reasons"])
        alerts.append(item)
    return alerts


def get_timeline(model_version: str | None = None) -> list[dict[str, Any]]:
    selected = _selected_model_version(model_version)
    sql = """
        SELECT
            date_trunc('hour', window_start) AS bucket,
            count(*) AS total_windows,
            count(*) FILTER (WHERE is_security_relevant) AS security_relevant_windows,
            count(*) FILTER (WHERE threat_level IN ('high', 'critical')) AS high_or_critical_windows,
            max(threat_score) AS max_threat_score,
            max(anomaly_score) AS max_anomaly_score
        FROM analytics.request_ip_threat_scores
        WHERE model_version = %s
        GROUP BY bucket
        ORDER BY bucket DESC
        LIMIT 48
    """
    columns = [
        "bucket",
        "total_windows",
        "security_relevant_windows",
        "high_or_critical_windows",
        "max_threat_score",
        "max_anomaly_score",
    ]
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, (selected,))
            rows = cursor.fetchall()
    return [dict(zip(columns, row, strict=True)) for row in rows]


def get_evaluation_summary() -> dict[str, Any]:
    latest_eval_sql = """
        SELECT evaluation_id
        FROM analytics.synthetic_scenario_metrics
        ORDER BY created_at DESC
        LIMIT 1
    """
    metrics_sql = """
        SELECT ranking_method, metric_name, k_value, metric_value
        FROM analytics.synthetic_scenario_metrics
        WHERE evaluation_id = %s
        ORDER BY ranking_method, metric_name, k_value
    """
    scenario_sql = """
        SELECT
            scenario_name,
            is_attack_like,
            count(*) AS rows,
            avg(anomaly_score) AS avg_anomaly_score,
            avg(threat_score) AS avg_threat_score,
            count(*) FILTER (WHERE is_security_relevant) AS security_relevant_rows
        FROM analytics.synthetic_scenario_scores
        WHERE evaluation_id = %s
        GROUP BY scenario_name, is_attack_like
        ORDER BY is_attack_like DESC, scenario_name
    """
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(latest_eval_sql)
            row = cursor.fetchone()
            if row is None:
                return {"evaluation_id": None, "metrics": [], "scenarios": []}
            evaluation_id = str(row[0])

            cursor.execute(metrics_sql, (evaluation_id,))
            metrics = [
                {
                    "ranking_method": str(metric_row[0]),
                    "metric_name": str(metric_row[1]),
                    "k_value": int(metric_row[2]),
                    "metric_value": float(metric_row[3]),
                }
                for metric_row in cursor.fetchall()
            ]

            cursor.execute(scenario_sql, (evaluation_id,))
            scenarios = [
                {
                    "scenario_name": str(scenario_row[0]),
                    "is_attack_like": bool(scenario_row[1]),
                    "rows": int(scenario_row[2]),
                    "avg_anomaly_score": float(scenario_row[3] or 0.0),
                    "avg_threat_score": float(scenario_row[4] or 0.0),
                    "security_relevant_rows": int(scenario_row[5] or 0),
                }
                for scenario_row in cursor.fetchall()
            ]

    return {"evaluation_id": evaluation_id, "metrics": metrics, "scenarios": scenarios}


def get_incident_summary(model_version: str | None = None) -> dict[str, Any]:
    selected = _selected_model_version(model_version)
    latest_date_sql = """
        SELECT max(window_start::date)
        FROM analytics.request_ip_threat_scores
        WHERE model_version = %s
    """
    sql = """
        SELECT
            t.window_start,
            t.ip_hash,
            t.model_version,
            t.threat_score,
            t.threat_level,
            t.is_security_relevant,
            t.anomaly_score,
            t.anomaly_rank,
            t.request_count,
            t.suspicious_path_count,
            t.error_count,
            t.error_rate,
            t.unique_endpoint_count,
            t.static_asset_count,
            t.off_hours,
            t.reasons,
            context.module_id,
            context.endpoint_template,
            context.endpoint_group,
            context.status_family
        FROM analytics.request_ip_threat_scores t
        LEFT JOIN LATERAL (
            SELECT
                r.module_id,
                r.endpoint_template,
                r.endpoint_group,
                r.status_family,
                count(*) AS event_count
            FROM analytics.request_logs r
            WHERE r.ip_hash = t.ip_hash
              AND r.timestamp >= t.window_start
              AND r.timestamp < t.window_start + interval '5 minutes'
            GROUP BY r.module_id, r.endpoint_template, r.endpoint_group, r.status_family
            ORDER BY count(*) DESC, r.endpoint_template ASC
            LIMIT 1
        ) context ON true
        WHERE t.model_version = %s
          AND t.window_start::date = %s
        ORDER BY t.threat_score DESC, t.anomaly_score DESC, t.window_start DESC
        LIMIT 10
    """
    columns = [
        "window_start",
        "ip_hash",
        "model_version",
        "threat_score",
        "threat_level",
        "is_security_relevant",
        "anomaly_score",
        "anomaly_rank",
        "request_count",
        "suspicious_path_count",
        "error_count",
        "error_rate",
        "unique_endpoint_count",
        "static_asset_count",
        "off_hours",
        "reasons",
        "module_id",
        "endpoint_template",
        "endpoint_group",
        "status_family",
    ]
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(latest_date_sql, (selected,))
            latest_row = cursor.fetchone()
            latest_date = latest_row[0] if latest_row else None
            if latest_date is None:
                return {
                    "model_version": selected,
                    "date": datetime.now().date(),
                    "interpretation": "No case-review windows are available for the selected model.",
                    "windows": [],
                }

            cursor.execute(sql, (selected, latest_date))
            rows = cursor.fetchall()
    windows = []
    for row in rows:
        item = dict(zip(columns, row, strict=True))
        item["reasons"] = _json_list(item["reasons"])
        windows.append(item)
    return {
        "model_version": selected,
        "date": latest_date,
        "interpretation": (
            "Latest processed request-log windows are shown for case review. High scores indicate "
            "prioritized investigation candidates, not confirmed compromise."
        ),
        "windows": windows,
    }
