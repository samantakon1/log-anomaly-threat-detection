# Dashboard User Guide

The dashboard is a thesis prototype for reviewing processed anomaly-detection and threat-scoring outputs. It does not access raw private logs and does not train models from the browser.

## Local Services

Start the backend API from the project root:

```bash
.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8012
```

Start the frontend from the thesis workspace root or project root:

```bash
npm --prefix log-anomaly-threat-detection/frontend run dev -- --host 127.0.0.1 --port 5173
```

Open:

```text
http://127.0.0.1:5173/
```

## Dashboard Sections

| Section | Purpose |
| --- | --- |
| Overview | Shows feature-window counts, security-relevant windows, high/critical windows, threat-level distribution, and hourly threat timeline. |
| Alerts | Shows top anonymized threat-scored windows with anomaly score, threat score, IP hash, endpoint template, request counts, error rate, and reason codes. |
| Case Review | Shows a selected high-priority suspicious period as a case-validation example, not as confirmed compromise. |
| Evaluation | Shows synthetic evaluation metrics and scenario-level results. |
| Demo | Starts controlled latest-log processing or analysis runs and shows terminal-style progress output. |

## Demo Controls

The Demo tab contains two actions:

- `Get & Process Latest Logs` retrieves App Engine request logs through the local `gcloud` CLI, anonymizes and generalizes them, and loads the safe rows into PostgreSQL.
- `Analyse Latest Logs` rebuilds feature windows, trains the current anomaly model, applies threat scoring, refreshes synthetic evaluation, and updates dashboard-ready tables.

The terminal output is cleared every time a new action starts. While one action is running, both buttons remain disabled so the same process cannot be started twice.

The first retrieval uses the configured recent-log freshness window. After a successful retrieval, the backend stores the newest processed log timestamp in `analytics.demo_ingestion_state`. Later retrievals start from that stored timestamp with a small overlap, so late-arriving log records are still captured. Already processed records are safe because request logs are deduplicated by `request_hash`.

## Privacy Rules

- The dashboard displays anonymized hashes, endpoint templates, aggregate counts, and reason codes.
- Raw IP addresses, real users, tenants, domains, tokens, payloads, and raw private logs are not displayed.
- A critical alert is an investigation priority, not proof of compromise or attribution.
