# Controlled Demo Mode

This document records a future dashboard extension for the thesis defense demonstration. It is kept outside the thesis text and describes a reproducible local run of the implemented pipeline.

## Purpose

The demo mode presents an end-to-end processing flow inside the dashboard. A presenter can retrieve and process recent App Engine request logs, then start a separate analysis run that rebuilds features, retrains the anomaly model, applies threat scoring, and refreshes dashboard outputs.

The implementation uses the local `gcloud` CLI for latest-log retrieval and immediately writes raw exports only to the private raw-log folder. Dashboard output shows processing status and sanitized errors, not raw log content.

The retrieval step uses a database high-water mark. The backend stores the newest processed App Engine log timestamp in `analytics.demo_ingestion_state`; the next retrieval starts from that timestamp with a small overlap to avoid missing delayed log entries. Duplicate records remain safe because the request-log table uses `request_hash` conflict handling.

## Input

```text
app_engine_logs/anonymized/demo_live_logs.jsonl
```

The input file contains only anonymized and generalized records. It follows the same field structure as the existing request-log dataset.

## Dashboard Flow

1. Open the dashboard Demo tab.
2. Select `Get & Process Latest Logs`.
3. Display retrieval, anonymization, generalization, and database-loading progress in the terminal panel.
4. Select `Analyse Latest Logs`.
5. Display feature building, anomaly model training, threat scoring, and evaluation progress in the terminal panel.
6. Refresh the dashboard views after analysis completes.

## Progress States

| Step | UI message |
| --- | --- |
| 1 | Loading anonymized demo logs |
| 2 | Validating generalized endpoint paths |
| 3 | Writing processed rows into PostgreSQL |
| 4 | Rebuilding feature windows |
| 5 | Scoring anomaly windows |
| 6 | Applying threat prioritization |
| 7 | Refreshing dashboard results |

## API Design

```text
POST /api/demo/get-process-latest
POST /api/demo/analyse-latest
GET /api/demo/status
```

Processing sequence:

```text
latest App Engine request logs
        |
validation and safety checks
        |
anonymization and endpoint generalization
        |
PostgreSQL insert
        |
feature-window rebuild
        |
anomaly scoring
        |
threat scoring
        |
dashboard refresh
```

## Run Tracking

```sql
CREATE TABLE analytics.demo_ingestion_state (
    source_name TEXT PRIMARY KEY,
    last_log_timestamp TIMESTAMPTZ,
    last_successful_run_id TEXT,
    last_successful_run_at TIMESTAMPTZ,
    last_rows_retrieved INTEGER DEFAULT 0,
    last_raw_path TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## Interface States

| State | Behavior |
| --- | --- |
| Idle | The run button is enabled. |
| Running | The run button is disabled and the active progress step is visible. |
| Completed | Dashboard data reloads from the API. |
| Failed | A sanitized error message is displayed without raw log details. |

## Safety Controls

- No raw production logs are fetched during the demo.
- No raw IPs, domains, users, tenants, tokens, payloads, or credentials are displayed.
- Only anonymized and generalized input is processed.
- A running demo action disables both demo buttons until it finishes or fails.
- The terminal output is cleared at the start of every new action.
- The demo dataset remains small enough for a short presentation run.
- Static screenshots are prepared as a presentation fallback.
