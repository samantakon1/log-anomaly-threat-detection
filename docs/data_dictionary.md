# Data Dictionary

This document will be expanded as implementation progresses. The project uses only anonymized and generalized log fields.

## Request Logs

Primary file: `app_engine_request_logs_30d_2026-06-08.generalized.jsonl`

Important fields include `timestamp`, `module_id`, `method`, `status_code`, `status_family`, `latency_ms`, `response_size`, `ip_hash`, `endpoint_group`, `endpoint_template`, `user_agent_category`, and suspicious-path indicators.

## Structured Application Logs

Secondary file: `app_engine_stdout_structured_7d_2026-06-08.generalized.jsonl`

Important fields include `timestamp`, `level`, `event`, `method`, `status_code`, `status_family`, `response_time_ms`, `user_id_hash`, `tenant_hash`, `endpoint_group`, `endpoint_template`, and error/sensitive-key indicators.

The database table also stores an `event_hash` generated from the full anonymized/generalized event. This is used as the app-log uniqueness key because multiple structured application events can share the same request hash.
