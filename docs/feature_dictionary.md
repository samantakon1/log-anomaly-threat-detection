# Feature Dictionary

The first implementation uses 5-minute behavioral windows. These features are stored in PostgreSQL and are generated from anonymized/generalized logs only.

## Request IP-Window Features

Table: `analytics.request_ip_window_features`

Grain: one row per `ip_hash` per 5-minute `window_start`.

| Feature | Meaning |
| --- | --- |
| `request_count` | Number of requests from the IP hash in the window. |
| `unique_endpoint_count` | Number of distinct generalized endpoint templates requested. |
| `unique_endpoint_group_count` | Number of endpoint groups used, such as `api`, `static_asset`, or `suspicious_probe`. |
| `unique_method_count` | Number of distinct HTTP methods used. |
| `unique_user_agent_category_count` | Number of user-agent categories used by the IP hash. |
| `static_asset_count` | Number of requests to static assets. |
| `suspicious_path_count` | Number of requests matching suspicious path patterns. |
| `sensitive_query_count` | Number of requests containing sensitive query-key names. |
| `status_2xx_count`, `status_3xx_count`, `status_4xx_count`, `status_5xx_count` | HTTP status-family counts. |
| `error_count` | Number of 4xx and 5xx responses. |
| `error_rate` | Error count divided by total request count. |
| `avg_latency_ms`, `p95_latency_ms`, `max_latency_ms` | Latency behavior in the window. |
| `avg_response_size` | Average response size. |
| `avg_endpoint_rarity` | Average rarity of endpoint templates, calculated from global endpoint frequency. |
| `off_hours` | Whether the window is between 22:00 and 05:59 UTC. |

## Application User-Window Features

Table: `analytics.app_user_window_features`

Grain: one row per `user_id_hash` per 5-minute `window_start`.

| Feature | Meaning |
| --- | --- |
| `event_count` | Number of structured application log events for the user in the window. |
| `unique_tenant_count` | Number of tenant hashes seen for the user. |
| `unique_endpoint_count` | Number of distinct generalized endpoint templates. |
| `unique_endpoint_group_count` | Number of distinct endpoint groups. |
| `unique_method_count` | Number of distinct HTTP methods. |
| `suspicious_path_count` | Number of suspicious endpoint-pattern events. |
| `error_count` | Number of application events marked as errors. |
| `error_rate` | Error count divided by event count. |
| `status_2xx_count`, `status_4xx_count` | Application status-family counts currently available in structured logs. |
| `avg_response_time_ms`, `p95_response_time_ms`, `max_response_time_ms` | Response-time behavior in the window. |
| `request_sensitive_key_count`, `response_sensitive_key_count`, `header_sensitive_key_count` | Counts of rows where generalized sensitive-key indicators were present. |
| `off_hours` | Whether the window is between 22:00 and 05:59 UTC. |

## Model Use

The first baseline anomaly model uses numeric columns from `analytics.request_ip_window_features`. Scores are stored in `analytics.request_ip_anomaly_scores`.

The second-stage threat scoring layer combines the anomaly score with security indicators such as suspicious path count, error rate, request volume, endpoint diversity, and off-hours behavior. Threat scores are stored in `analytics.request_ip_threat_scores`.
