from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from psycopg.types.json import Jsonb

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from log_anomaly_threat_detection.data_loading import load_dataset_config, load_jsonl
from log_anomaly_threat_detection.database import apply_schema, connect


def as_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def stable_event_hash(row: dict[str, Any]) -> str:
    payload = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_request_logs(rows: list[dict[str, Any]], batch_size: int = 1000) -> int:
    sql = """
        INSERT INTO analytics.request_logs (
            timestamp, module_id, version_id, method, status_code, status_family,
            latency_ms, response_size, ip_hash, user_agent_category, endpoint_group,
            endpoint_template, path_depth, path_length, is_static_asset,
            has_suspicious_path_pattern, has_sensitive_query_key, request_hash, raw_record
        )
        VALUES (
            %(timestamp)s, %(module_id)s, %(version_id)s, %(method)s, %(status_code)s,
            %(status_family)s, %(latency_ms)s, %(response_size)s, %(ip_hash)s,
            %(user_agent_category)s, %(endpoint_group)s, %(endpoint_template)s,
            %(path_depth)s, %(path_length)s, %(is_static_asset)s,
            %(has_suspicious_path_pattern)s, %(has_sensitive_query_key)s,
            %(request_hash)s, %(raw_record)s
        )
        ON CONFLICT (request_hash) DO UPDATE SET
            timestamp = EXCLUDED.timestamp,
            module_id = EXCLUDED.module_id,
            version_id = EXCLUDED.version_id,
            method = EXCLUDED.method,
            status_code = EXCLUDED.status_code,
            status_family = EXCLUDED.status_family,
            latency_ms = EXCLUDED.latency_ms,
            response_size = EXCLUDED.response_size,
            ip_hash = EXCLUDED.ip_hash,
            user_agent_category = EXCLUDED.user_agent_category,
            endpoint_group = EXCLUDED.endpoint_group,
            endpoint_template = EXCLUDED.endpoint_template,
            path_depth = EXCLUDED.path_depth,
            path_length = EXCLUDED.path_length,
            is_static_asset = EXCLUDED.is_static_asset,
            has_suspicious_path_pattern = EXCLUDED.has_suspicious_path_pattern,
            has_sensitive_query_key = EXCLUDED.has_sensitive_query_key,
            raw_record = EXCLUDED.raw_record,
            loaded_at = now()
    """
    inserted = 0
    with connect() as conn:
        with conn.cursor() as cursor:
            for start in range(0, len(rows), batch_size):
                batch = []
                for row in rows[start:start + batch_size]:
                    batch.append({
                        "timestamp": row.get("timestamp"),
                        "module_id": row.get("module_id"),
                        "version_id": row.get("version_id"),
                        "method": row.get("method"),
                        "status_code": as_int(row.get("status_code")),
                        "status_family": row.get("status_family"),
                        "latency_ms": as_float(row.get("latency_ms")),
                        "response_size": as_int(row.get("response_size")),
                        "ip_hash": row.get("ip_hash"),
                        "user_agent_category": row.get("user_agent_category"),
                        "endpoint_group": row.get("endpoint_group"),
                        "endpoint_template": row.get("endpoint_template"),
                        "path_depth": as_int(row.get("path_depth")),
                        "path_length": as_int(row.get("path_length")),
                        "is_static_asset": row.get("is_static_asset"),
                        "has_suspicious_path_pattern": row.get("has_suspicious_path_pattern"),
                        "has_sensitive_query_key": row.get("has_sensitive_query_key"),
                        "request_hash": row.get("request_hash"),
                        "raw_record": Jsonb(row),
                    })
                cursor.executemany(sql, batch)
                inserted += cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
        conn.commit()
    return inserted


def load_app_logs(rows: list[dict[str, Any]], batch_size: int = 1000) -> int:
    sql = """
        INSERT INTO analytics.app_logs (
            timestamp, receive_timestamp, module_id, version_id, level, event, method,
            status_code, status_family, response_time_ms, user_id_hash, tenant_hash,
            endpoint_group, endpoint_template, path_depth, path_length, is_static_asset,
            has_suspicious_path_pattern, has_error, request_data_has_sensitive_key,
            response_data_has_sensitive_key, headers_has_sensitive_key, request_hash, event_hash, raw_record
        )
        VALUES (
            %(timestamp)s, %(receive_timestamp)s, %(module_id)s, %(version_id)s,
            %(level)s, %(event)s, %(method)s, %(status_code)s, %(status_family)s,
            %(response_time_ms)s, %(user_id_hash)s, %(tenant_hash)s,
            %(endpoint_group)s, %(endpoint_template)s, %(path_depth)s, %(path_length)s,
            %(is_static_asset)s, %(has_suspicious_path_pattern)s, %(has_error)s,
            %(request_data_has_sensitive_key)s, %(response_data_has_sensitive_key)s,
            %(headers_has_sensitive_key)s, %(request_hash)s, %(event_hash)s, %(raw_record)s
        )
        ON CONFLICT (event_hash) DO NOTHING
    """
    inserted = 0
    with connect() as conn:
        with conn.cursor() as cursor:
            for start in range(0, len(rows), batch_size):
                batch = []
                for row in rows[start:start + batch_size]:
                    batch.append({
                        "timestamp": row.get("timestamp"),
                        "receive_timestamp": row.get("receive_timestamp"),
                        "module_id": row.get("module_id"),
                        "version_id": row.get("version_id"),
                        "level": row.get("level"),
                        "event": row.get("event"),
                        "method": row.get("method"),
                        "status_code": as_int(row.get("status_code")),
                        "status_family": row.get("status_family"),
                        "response_time_ms": as_float(row.get("response_time_ms")),
                        "user_id_hash": row.get("user_id_hash"),
                        "tenant_hash": row.get("tenant_hash"),
                        "endpoint_group": row.get("endpoint_group"),
                        "endpoint_template": row.get("endpoint_template"),
                        "path_depth": as_int(row.get("path_depth")),
                        "path_length": as_int(row.get("path_length")),
                        "is_static_asset": row.get("is_static_asset"),
                        "has_suspicious_path_pattern": row.get("has_suspicious_path_pattern"),
                        "has_error": row.get("has_error"),
                        "request_data_has_sensitive_key": row.get("request_data_has_sensitive_key"),
                        "response_data_has_sensitive_key": row.get("response_data_has_sensitive_key"),
                        "headers_has_sensitive_key": row.get("headers_has_sensitive_key"),
                        "request_hash": row.get("request_hash"),
                        "event_hash": stable_event_hash(row),
                        "raw_record": Jsonb(row),
                    })
                cursor.executemany(sql, batch)
                inserted += cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
        conn.commit()
    return inserted


def clear_app_logs_and_features() -> None:
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute("TRUNCATE TABLE analytics.app_user_window_features")
            cursor.execute("TRUNCATE TABLE analytics.app_logs RESTART IDENTITY")
        conn.commit()


def load_quality_metrics(path: Path, dataset: str) -> int:
    sql = """
        INSERT INTO analytics.dataset_quality_metrics (dataset, metric, value)
        VALUES (%s, %s, %s)
        ON CONFLICT (dataset, metric) DO UPDATE
        SET value = EXCLUDED.value,
            loaded_at = now()
    """
    rows = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            rows.append((dataset, row["metric"], row["value"]))

    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.executemany(sql, rows)
        conn.commit()
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Load anonymized/generalized thesis log datasets into PostgreSQL.")
    parser.add_argument("--schema-only", action="store_true", help="Create tables and indexes without loading data.")
    parser.add_argument("--skip-request-logs", action="store_true", help="Do not load the request-log dataset.")
    parser.add_argument("--skip-app-logs", action="store_true", help="Do not load the structured application-log dataset.")
    parser.add_argument(
        "--request-path",
        default=None,
        help="Optional request-log JSONL path to load instead of the configured primary request dataset.",
    )
    parser.add_argument(
        "--request-dataset-name",
        default="request_logs_custom",
        help="Dataset name used when --request-path is provided.",
    )
    args = parser.parse_args()

    apply_schema()
    if args.schema_only:
        print("Schema is ready.")
        return

    datasets = load_dataset_config()

    if not args.skip_request_logs:
        request_path = args.request_path or datasets["request_logs_30d"]["path"]
        request_dataset_name = args.request_dataset_name if args.request_path else "request_logs_30d"
        request_rows = load_jsonl(request_path)
        inserted = load_request_logs(request_rows)
        print(f"Request logs processed: {len(request_rows):,}; inserted: {inserted:,}")
        if not args.request_path:
            metrics = load_quality_metrics(PROJECT_ROOT / "reports/tables/request_log_quality.csv", request_dataset_name)
            print(f"Request quality metrics upserted: {metrics:,}")

    if not args.skip_app_logs:
        clear_app_logs_and_features()
        app_rows = load_jsonl(datasets["app_logs_7d"]["path"])
        inserted = load_app_logs(app_rows)
        print(f"Application logs processed: {len(app_rows):,}; inserted: {inserted:,}")
        metrics = load_quality_metrics(PROJECT_ROOT / "reports/tables/app_log_quality.csv", "app_logs_7d")
        print(f"Application quality metrics upserted: {metrics:,}")


if __name__ == "__main__":
    main()
