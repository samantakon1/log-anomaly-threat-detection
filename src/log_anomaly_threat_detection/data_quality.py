from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any
import csv


def parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def missing_count(rows: list[dict[str, Any]], column: str) -> int:
    return sum(1 for row in rows if row.get(column) in (None, ""))


def numeric_values(rows: list[dict[str, Any]], column: str) -> list[float]:
    values: list[float] = []
    for row in rows:
        value = row.get(column)
        if value in (None, ""):
            continue
        try:
            values.append(float(value))
        except (TypeError, ValueError):
            continue
    return values


def percentile(values: list[float], percent: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, round((len(ordered) - 1) * percent))
    return ordered[index]


def top_counts(rows: list[dict[str, Any]], column: str, limit: int = 10) -> list[tuple[str, int]]:
    counter = Counter(str(row.get(column, "missing") or "missing") for row in rows)
    return counter.most_common(limit)


def summarize_common(rows: list[dict[str, Any]], dataset_name: str) -> dict[str, Any]:
    timestamps = [parse_timestamp(row.get("timestamp")) for row in rows]
    timestamps = [item for item in timestamps if item is not None]
    columns = sorted({key for row in rows for key in row.keys()})
    return {
        "dataset": dataset_name,
        "row_count": len(rows),
        "column_count": len(columns),
        "start_time": min(timestamps).isoformat() if timestamps else "",
        "end_time": max(timestamps).isoformat() if timestamps else "",
        "columns": columns,
    }


def summarize_request_logs(rows: list[dict[str, Any]], dataset_name: str) -> dict[str, Any]:
    summary = summarize_common(rows, dataset_name)
    latencies = numeric_values(rows, "latency_ms")
    response_sizes = numeric_values(rows, "response_size")
    summary.update({
        "missing_timestamp": missing_count(rows, "timestamp"),
        "missing_ip_hash": missing_count(rows, "ip_hash"),
        "missing_endpoint_template": missing_count(rows, "endpoint_template"),
        "unique_ip_hashes": len({row.get("ip_hash") for row in rows if row.get("ip_hash")}),
        "unique_endpoint_templates": len({row.get("endpoint_template") for row in rows if row.get("endpoint_template")}),
        "suspicious_path_rows": sum(1 for row in rows if bool(row.get("has_suspicious_path_pattern"))),
        "sensitive_query_rows": sum(1 for row in rows if bool(row.get("has_sensitive_query_key"))),
        "latency_avg_ms": round(mean(latencies), 3) if latencies else None,
        "latency_p95_ms": percentile(latencies, 0.95),
        "latency_max_ms": max(latencies) if latencies else None,
        "response_size_avg": round(mean(response_sizes), 3) if response_sizes else None,
        "status_family_top": top_counts(rows, "status_family"),
        "method_top": top_counts(rows, "method"),
        "module_top": top_counts(rows, "module_id"),
        "endpoint_group_top": top_counts(rows, "endpoint_group"),
        "user_agent_category_top": top_counts(rows, "user_agent_category"),
    })
    return summary


def summarize_app_logs(rows: list[dict[str, Any]], dataset_name: str) -> dict[str, Any]:
    summary = summarize_common(rows, dataset_name)
    response_times = numeric_values(rows, "response_time_ms")
    summary.update({
        "missing_timestamp": missing_count(rows, "timestamp"),
        "missing_user_id_hash": missing_count(rows, "user_id_hash"),
        "missing_tenant_hash": missing_count(rows, "tenant_hash"),
        "missing_endpoint_template": missing_count(rows, "endpoint_template"),
        "unique_user_hashes": len({row.get("user_id_hash") for row in rows if row.get("user_id_hash")}),
        "unique_tenant_hashes": len({row.get("tenant_hash") for row in rows if row.get("tenant_hash")}),
        "unique_endpoint_templates": len({row.get("endpoint_template") for row in rows if row.get("endpoint_template")}),
        "error_rows": sum(1 for row in rows if bool(row.get("has_error"))),
        "suspicious_path_rows": sum(1 for row in rows if bool(row.get("has_suspicious_path_pattern"))),
        "request_sensitive_key_rows": sum(1 for row in rows if bool(row.get("request_data_has_sensitive_key"))),
        "response_time_avg_ms": round(mean(response_times), 3) if response_times else None,
        "response_time_p95_ms": percentile(response_times, 0.95),
        "response_time_max_ms": max(response_times) if response_times else None,
        "level_top": top_counts(rows, "level"),
        "method_top": top_counts(rows, "method"),
        "status_family_top": top_counts(rows, "status_family"),
        "endpoint_group_top": top_counts(rows, "endpoint_group"),
    })
    return summary


def write_quality_csv(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    scalar_items = {key: value for key, value in summary.items() if not isinstance(value, (list, tuple))}
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["metric", "value"])
        for key, value in scalar_items.items():
            writer.writerow([key, value])


def format_top_counts(title: str, values: list[tuple[str, int]]) -> str:
    lines = [f"### {title}", "", "| Value | Count |", "| --- | ---: |"]
    lines.extend(f"| {value} | {count} |" for value, count in values)
    return "\n".join(lines)


def format_summary_markdown(request_summary: dict[str, Any], app_summary: dict[str, Any]) -> str:
    lines = [
        "# Dataset Quality Summary",
        "",
        "This report is generated from anonymized/generalized log files only. It must not include raw IP addresses, user identifiers, tenant names, domains, payloads, tokens, or client names.",
        "",
        "## Request Logs: 30-Day Dataset",
        "",
        f"- Rows: {request_summary["row_count"]:,}",
        f"- Columns: {request_summary["column_count"]}",
        f"- Time range: {request_summary["start_time"]} to {request_summary["end_time"]}",
        f"- Unique IP hashes: {request_summary["unique_ip_hashes"]:,}",
        f"- Unique endpoint templates: {request_summary["unique_endpoint_templates"]:,}",
        f"- Suspicious path rows: {request_summary["suspicious_path_rows"]:,}",
        f"- Sensitive query rows: {request_summary["sensitive_query_rows"]:,}",
        f"- Average latency: {request_summary["latency_avg_ms"]} ms",
        f"- P95 latency: {request_summary["latency_p95_ms"]} ms",
        f"- Maximum latency: {request_summary["latency_max_ms"]} ms",
        "",
        format_top_counts("Request Status Families", request_summary["status_family_top"]),
        "",
        format_top_counts("Request Endpoint Groups", request_summary["endpoint_group_top"]),
        "",
        format_top_counts("Request User-Agent Categories", request_summary["user_agent_category_top"]),
        "",
        "## Structured Application Logs: 7-Day Dataset",
        "",
        f"- Rows: {app_summary["row_count"]:,}",
        f"- Columns: {app_summary["column_count"]}",
        f"- Time range: {app_summary["start_time"]} to {app_summary["end_time"]}",
        f"- Unique user hashes: {app_summary["unique_user_hashes"]:,}",
        f"- Unique tenant hashes: {app_summary["unique_tenant_hashes"]:,}",
        f"- Unique endpoint templates: {app_summary["unique_endpoint_templates"]:,}",
        f"- Error rows: {app_summary["error_rows"]:,}",
        f"- Suspicious path rows: {app_summary["suspicious_path_rows"]:,}",
        f"- Request sensitive-key rows: {app_summary["request_sensitive_key_rows"]:,}",
        f"- Average response time: {app_summary["response_time_avg_ms"]} ms",
        f"- P95 response time: {app_summary["response_time_p95_ms"]} ms",
        f"- Maximum response time: {app_summary["response_time_max_ms"]} ms",
        "",
        format_top_counts("Application Log Levels", app_summary["level_top"]),
        "",
        format_top_counts("Application Status Families", app_summary["status_family_top"]),
        "",
        format_top_counts("Application Endpoint Groups", app_summary["endpoint_group_top"]),
        "",
        "## Implementation Notes",
        "",
        "- These summaries confirm the first implementation can load the anonymized datasets and generate thesis-ready descriptive statistics.",
        "- The request-log dataset remains the primary implementation dataset because it has the largest row count and richer web request behavior.",
        "- The structured application-log dataset supports user-, tenant-, and error-oriented feature analysis after request-log baseline processing.",
    ]
    return "\n".join(lines) + "\n"
