from __future__ import annotations

from typing import Any

from log_anomaly_threat_detection.database import connect


REQUEST_IP_FEATURE_SQL = """
WITH endpoint_frequency AS (
    SELECT
        endpoint_template,
        count(*) AS endpoint_count,
        sum(count(*)) OVER () AS total_count
    FROM analytics.request_logs
    GROUP BY endpoint_template
),
base AS (
    SELECT
        date_trunc('hour', r.timestamp)
            + (floor(extract(minute from r.timestamp) / 5)::int * interval '5 minutes') AS window_start,
        r.ip_hash,
        r.endpoint_template,
        r.endpoint_group,
        r.method,
        r.user_agent_category,
        r.status_family,
        r.latency_ms,
        r.response_size,
        r.is_static_asset,
        r.has_suspicious_path_pattern,
        r.has_sensitive_query_key,
        -ln(ef.endpoint_count::double precision / NULLIF(ef.total_count, 0)) AS endpoint_rarity
    FROM analytics.request_logs r
    LEFT JOIN endpoint_frequency ef ON ef.endpoint_template = r.endpoint_template
    WHERE r.ip_hash IS NOT NULL
),
features AS (
    SELECT
        window_start,
        ip_hash,
        count(*)::int AS request_count,
        count(DISTINCT endpoint_template)::int AS unique_endpoint_count,
        count(DISTINCT endpoint_group)::int AS unique_endpoint_group_count,
        count(DISTINCT method)::int AS unique_method_count,
        count(DISTINCT user_agent_category)::int AS unique_user_agent_category_count,
        count(*) FILTER (WHERE is_static_asset)::int AS static_asset_count,
        count(*) FILTER (WHERE has_suspicious_path_pattern)::int AS suspicious_path_count,
        count(*) FILTER (WHERE has_sensitive_query_key)::int AS sensitive_query_count,
        count(*) FILTER (WHERE status_family = '2xx')::int AS status_2xx_count,
        count(*) FILTER (WHERE status_family = '3xx')::int AS status_3xx_count,
        count(*) FILTER (WHERE status_family = '4xx')::int AS status_4xx_count,
        count(*) FILTER (WHERE status_family = '5xx')::int AS status_5xx_count,
        count(*) FILTER (WHERE status_family IN ('4xx', '5xx'))::int AS error_count,
        (
            count(*) FILTER (WHERE status_family IN ('4xx', '5xx'))::double precision
            / NULLIF(count(*), 0)
        ) AS error_rate,
        avg(latency_ms) AS avg_latency_ms,
        percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_latency_ms,
        max(latency_ms) AS max_latency_ms,
        avg(response_size) AS avg_response_size,
        avg(endpoint_rarity) AS avg_endpoint_rarity,
        (extract(hour from window_start) < 6 OR extract(hour from window_start) >= 22) AS off_hours
    FROM base
    GROUP BY window_start, ip_hash
)
INSERT INTO analytics.request_ip_window_features (
    window_start,
    ip_hash,
    request_count,
    unique_endpoint_count,
    unique_endpoint_group_count,
    unique_method_count,
    unique_user_agent_category_count,
    static_asset_count,
    suspicious_path_count,
    sensitive_query_count,
    status_2xx_count,
    status_3xx_count,
    status_4xx_count,
    status_5xx_count,
    error_count,
    error_rate,
    avg_latency_ms,
    p95_latency_ms,
    max_latency_ms,
    avg_response_size,
    avg_endpoint_rarity,
    off_hours,
    generated_at
)
SELECT
    window_start,
    ip_hash,
    request_count,
    unique_endpoint_count,
    unique_endpoint_group_count,
    unique_method_count,
    unique_user_agent_category_count,
    static_asset_count,
    suspicious_path_count,
    sensitive_query_count,
    status_2xx_count,
    status_3xx_count,
    status_4xx_count,
    status_5xx_count,
    error_count,
    COALESCE(error_rate, 0.0),
    avg_latency_ms,
    p95_latency_ms,
    max_latency_ms,
    avg_response_size,
    avg_endpoint_rarity,
    off_hours,
    now()
FROM features
ON CONFLICT (window_start, ip_hash) DO UPDATE SET
    request_count = EXCLUDED.request_count,
    unique_endpoint_count = EXCLUDED.unique_endpoint_count,
    unique_endpoint_group_count = EXCLUDED.unique_endpoint_group_count,
    unique_method_count = EXCLUDED.unique_method_count,
    unique_user_agent_category_count = EXCLUDED.unique_user_agent_category_count,
    static_asset_count = EXCLUDED.static_asset_count,
    suspicious_path_count = EXCLUDED.suspicious_path_count,
    sensitive_query_count = EXCLUDED.sensitive_query_count,
    status_2xx_count = EXCLUDED.status_2xx_count,
    status_3xx_count = EXCLUDED.status_3xx_count,
    status_4xx_count = EXCLUDED.status_4xx_count,
    status_5xx_count = EXCLUDED.status_5xx_count,
    error_count = EXCLUDED.error_count,
    error_rate = EXCLUDED.error_rate,
    avg_latency_ms = EXCLUDED.avg_latency_ms,
    p95_latency_ms = EXCLUDED.p95_latency_ms,
    max_latency_ms = EXCLUDED.max_latency_ms,
    avg_response_size = EXCLUDED.avg_response_size,
    avg_endpoint_rarity = EXCLUDED.avg_endpoint_rarity,
    off_hours = EXCLUDED.off_hours,
    generated_at = now();
"""


APP_USER_FEATURE_SQL = """
WITH base AS (
    SELECT
        date_trunc('hour', timestamp)
            + (floor(extract(minute from timestamp) / 5)::int * interval '5 minutes') AS window_start,
        user_id_hash,
        tenant_hash,
        endpoint_template,
        endpoint_group,
        method,
        status_family,
        response_time_ms,
        has_suspicious_path_pattern,
        has_error,
        request_data_has_sensitive_key,
        response_data_has_sensitive_key,
        headers_has_sensitive_key
    FROM analytics.app_logs
    WHERE user_id_hash IS NOT NULL
),
features AS (
    SELECT
        window_start,
        user_id_hash,
        count(*)::int AS event_count,
        count(DISTINCT tenant_hash)::int AS unique_tenant_count,
        count(DISTINCT endpoint_template)::int AS unique_endpoint_count,
        count(DISTINCT endpoint_group)::int AS unique_endpoint_group_count,
        count(DISTINCT method)::int AS unique_method_count,
        count(*) FILTER (WHERE has_suspicious_path_pattern)::int AS suspicious_path_count,
        count(*) FILTER (WHERE has_error)::int AS error_count,
        (count(*) FILTER (WHERE has_error)::double precision / NULLIF(count(*), 0)) AS error_rate,
        count(*) FILTER (WHERE status_family = '2xx')::int AS status_2xx_count,
        count(*) FILTER (WHERE status_family = '4xx')::int AS status_4xx_count,
        avg(response_time_ms) AS avg_response_time_ms,
        percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time_ms) AS p95_response_time_ms,
        max(response_time_ms) AS max_response_time_ms,
        count(*) FILTER (WHERE request_data_has_sensitive_key)::int AS request_sensitive_key_count,
        count(*) FILTER (WHERE response_data_has_sensitive_key)::int AS response_sensitive_key_count,
        count(*) FILTER (WHERE headers_has_sensitive_key)::int AS header_sensitive_key_count,
        (extract(hour from window_start) < 6 OR extract(hour from window_start) >= 22) AS off_hours
    FROM base
    GROUP BY window_start, user_id_hash
)
INSERT INTO analytics.app_user_window_features (
    window_start,
    user_id_hash,
    event_count,
    unique_tenant_count,
    unique_endpoint_count,
    unique_endpoint_group_count,
    unique_method_count,
    suspicious_path_count,
    error_count,
    error_rate,
    status_2xx_count,
    status_4xx_count,
    avg_response_time_ms,
    p95_response_time_ms,
    max_response_time_ms,
    request_sensitive_key_count,
    response_sensitive_key_count,
    header_sensitive_key_count,
    off_hours,
    generated_at
)
SELECT
    window_start,
    user_id_hash,
    event_count,
    unique_tenant_count,
    unique_endpoint_count,
    unique_endpoint_group_count,
    unique_method_count,
    suspicious_path_count,
    error_count,
    COALESCE(error_rate, 0.0),
    status_2xx_count,
    status_4xx_count,
    avg_response_time_ms,
    p95_response_time_ms,
    max_response_time_ms,
    request_sensitive_key_count,
    response_sensitive_key_count,
    header_sensitive_key_count,
    off_hours,
    now()
FROM features
ON CONFLICT (window_start, user_id_hash) DO UPDATE SET
    event_count = EXCLUDED.event_count,
    unique_tenant_count = EXCLUDED.unique_tenant_count,
    unique_endpoint_count = EXCLUDED.unique_endpoint_count,
    unique_endpoint_group_count = EXCLUDED.unique_endpoint_group_count,
    unique_method_count = EXCLUDED.unique_method_count,
    suspicious_path_count = EXCLUDED.suspicious_path_count,
    error_count = EXCLUDED.error_count,
    error_rate = EXCLUDED.error_rate,
    status_2xx_count = EXCLUDED.status_2xx_count,
    status_4xx_count = EXCLUDED.status_4xx_count,
    avg_response_time_ms = EXCLUDED.avg_response_time_ms,
    p95_response_time_ms = EXCLUDED.p95_response_time_ms,
    max_response_time_ms = EXCLUDED.max_response_time_ms,
    request_sensitive_key_count = EXCLUDED.request_sensitive_key_count,
    response_sensitive_key_count = EXCLUDED.response_sensitive_key_count,
    header_sensitive_key_count = EXCLUDED.header_sensitive_key_count,
    off_hours = EXCLUDED.off_hours,
    generated_at = now();
"""


def build_request_ip_window_features() -> int:
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(REQUEST_IP_FEATURE_SQL)
            cursor.execute("SELECT count(*) FROM analytics.request_ip_window_features")
            count = cursor.fetchone()[0]
        conn.commit()
    return int(count)


def build_app_user_window_features() -> int:
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(APP_USER_FEATURE_SQL)
            cursor.execute("SELECT count(*) FROM analytics.app_user_window_features")
            count = cursor.fetchone()[0]
        conn.commit()
    return int(count)


def feature_table_summary() -> dict[str, Any]:
    sql = """
        SELECT
            (SELECT count(*) FROM analytics.request_ip_window_features) AS request_feature_rows,
            (SELECT count(*) FROM analytics.app_user_window_features) AS app_feature_rows,
            (SELECT max(request_count) FROM analytics.request_ip_window_features) AS max_request_count,
            (SELECT max(suspicious_path_count) FROM analytics.request_ip_window_features) AS max_suspicious_path_count,
            (SELECT max(event_count) FROM analytics.app_user_window_features) AS max_app_event_count,
            (SELECT max(error_count) FROM analytics.app_user_window_features) AS max_app_error_count
    """
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql)
            row = cursor.fetchone()
    return {
        "request_feature_rows": row[0],
        "app_feature_rows": row[1],
        "max_request_count": row[2],
        "max_suspicious_path_count": row[3],
        "max_app_event_count": row[4],
        "max_app_error_count": row[5],
    }
