# Log Anomaly Threat Detection

Implementation project for the MSc thesis **AI-Based Anomaly Detection Framework for Web Application Logs to Identify Cybersecurity Threats**.

The system processes anonymized and generalized web application logs, stores them in PostgreSQL, builds behavioral feature windows, trains a baseline anomaly detection model, applies a second-stage threat scoring layer, evaluates the ranking behavior on synthetic attack-like scenarios, and exposes the results through a FastAPI + React dashboard.

## Project Scope

This project is a thesis prototype, not a production SIEM. Its purpose is to demonstrate an end-to-end cybersecurity analytics workflow:

- ingest anonymized Google App Engine request logs and structured application logs;
- validate dataset quality before modeling;
- store only anonymized/generalized data in PostgreSQL;
- create IP-based and user-based behavioral feature windows;
- train an Isolation Forest baseline model on request-log feature windows;
- score anomalies and prioritize security-relevant windows with rule-based threat scoring;
- evaluate ranking quality with controlled synthetic scenarios;
- present overview, alerts, case review, and evaluation results in a web dashboard.

## Privacy Rules

Raw private logs must not be copied into this project.

The project expects anonymized/generalized datasets outside the repository:

```text
../app_engine_logs/anonymized/app_engine_request_logs_30d_2026-06-08.generalized.jsonl
../app_engine_logs/anonymized/app_engine_stdout_structured_7d_2026-06-08.generalized.jsonl
```

The dashboard and database contain only anonymized hashes, endpoint templates, aggregate counts, derived features, model scores, and reason codes. Do not store or display real IP addresses, user names, tenant names, domains, payloads, tokens, credentials, or raw private logs.

## Technology Stack

- Python 3.10+
- PostgreSQL
- FastAPI backend
- React 19 + Vite frontend
- scikit-learn Isolation Forest
- pandas, numpy, matplotlib, seaborn, pyarrow
- psycopg 3 for PostgreSQL access

## Folder Structure

```text
.
|-- backend/
|   `-- app/
|       |-- api.py
|       |-- main.py
|       `-- schemas.py
|-- config/
|   |-- datasets.yaml
|   `-- model.yaml
|-- docs/
|   |-- dashboard_user_guide.md
|   |-- data_dictionary.md
|   |-- database_setup.md
|   |-- deployment_notes.md
|   |-- feature_dictionary.md
|   `-- live_demo_plan.md
|-- frontend/
|   |-- src/
|   |   |-- main.tsx
|   |   `-- styles.css
|   |-- index.html
|   |-- package.json
|   |-- package-lock.json
|   |-- tsconfig.json
|   `-- vite.config.ts
|-- models/
|   `-- request_iforest_*.pkl
|-- reports/
|   |-- figures/
|   |-- summaries/
|   `-- tables/
|-- scripts/
|   |-- build_features.py
|   |-- load_anonymized_logs_to_db.py
|   |-- run_data_quality.py
|   |-- run_evaluation.py
|   |-- score_threats.py
|   `-- train_baseline.py
|-- sql/
|   `-- schema.sql
|-- src/
|   `-- log_anomaly_threat_detection/
|       |-- anomaly_detection.py
|       |-- dashboard_data.py
|       |-- data_loading.py
|       |-- data_quality.py
|       |-- database.py
|       |-- evaluation.py
|       |-- feature_engineering.py
|       |-- synthetic_scenarios.py
|       `-- threat_scoring.py
|-- tests/
|   `-- test_data_loading.py
|-- .env.example
|-- pyproject.toml
`-- README.md
```

## Prerequisites

Install or confirm:

```bash
python3 --version
psql --version
node --version
npm --version
```

PostgreSQL must be running locally, and the anonymized dataset files listed in `config/datasets.yaml` must exist relative to this project directory.

## Python Setup

Create and activate a local virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

The project dependencies are declared in `pyproject.toml`.

## Frontend Setup

Install frontend dependencies:

```bash
npm --prefix frontend install
```

The frontend dependencies are declared in `frontend/package.json`.

## Database Setup

Create a local PostgreSQL database and user. The expected defaults are:

```text
Database: log_anomaly_threat_detection
Username: log_anomaly_app
Host: localhost
Port: 5432
```

Copy the environment template:

```bash
cp .env.example .env
```

Edit `.env`:

```text
DB_HOST=localhost
DB_PORT=5432
DB_NAME=log_anomaly_threat_detection
DB_USER=log_anomaly_app
DB_PASSWORD=your_local_password
```

The code also supports `DATABASE_URL`, but the separate `DB_*` variables are safer when the password contains special URL characters. For detailed PostgreSQL commands, see `docs/database_setup.md`.

## End-to-End Pipeline

Run commands from the project root.

1. Generate dataset quality reports:

```bash
.venv/bin/python scripts/run_data_quality.py
```

Outputs:

```text
reports/summaries/dataset_quality_summary.md
reports/tables/request_log_quality.csv
reports/tables/app_log_quality.csv
```

2. Create/update PostgreSQL schema and load anonymized logs:

```bash
.venv/bin/python scripts/load_anonymized_logs_to_db.py
```

Useful options:

```bash
.venv/bin/python scripts/load_anonymized_logs_to_db.py --schema-only
.venv/bin/python scripts/load_anonymized_logs_to_db.py --skip-request-logs
.venv/bin/python scripts/load_anonymized_logs_to_db.py --skip-app-logs
```

3. Build feature windows:

```bash
.venv/bin/python scripts/build_features.py
```

This populates:

```text
analytics.request_ip_window_features
analytics.app_user_window_features
```

4. Train the baseline anomaly model:

```bash
.venv/bin/python scripts/train_baseline.py
```

Optional parameters:

```bash
.venv/bin/python scripts/train_baseline.py --random-state 42 --contamination auto
.venv/bin/python scripts/train_baseline.py --contamination 0.05
```

Outputs include a model artifact under `models/`, anomaly scores in PostgreSQL, and a summary under `reports/summaries/`.

5. Apply threat scoring:

```bash
.venv/bin/python scripts/score_threats.py
```

Optional model selection:

```bash
.venv/bin/python scripts/score_threats.py --model-version request_iforest_20260615_223730
```

6. Run synthetic evaluation:

```bash
.venv/bin/python scripts/run_evaluation.py
```

Optional parameters:

```bash
.venv/bin/python scripts/run_evaluation.py --rows-per-scenario 100 --random-state 42
.venv/bin/python scripts/run_evaluation.py --model-version request_iforest_20260615_223730
```

## Start the Backend

The backend reads dashboard data from PostgreSQL, so the database must be configured and populated first.

Start FastAPI from the project root:

```bash
.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8012
```

Check health:

```text
http://127.0.0.1:8012/health
```

API endpoints:

```text
GET /health
GET /api/overview
GET /api/alerts
GET /api/timeline
GET /api/evaluation
GET /api/incident
```

Useful alert filters:

```text
/api/alerts?limit=50
/api/alerts?threat_level=critical
/api/alerts?security_relevant=true
/api/alerts?ip_hash=<anonymized_hash>
```

## Start the Frontend

In another terminal, start Vite:

```bash
npm --prefix frontend run dev -- --host 127.0.0.1 --port 5173
```

Open:

```text
http://127.0.0.1:5173/
```

The frontend uses this default backend URL:

```text
http://127.0.0.1:8012
```

To override it:

```bash
VITE_API_BASE_URL=http://127.0.0.1:8012 npm --prefix frontend run dev -- --host 127.0.0.1 --port 5173
```

Build the production frontend:

```bash
npm --prefix frontend run build
```

Preview the production build:

```bash
npm --prefix frontend run preview
```

## Dashboard Views

- Overview: total windows, high anomaly score windows, security-relevant windows, threat distribution, and timeline.
- Alerts: highest-priority threat-scored windows with anomaly score, threat score, request counts, endpoint context, and reason codes.
- Case Review: selected suspicious period for thesis interpretation.
- Evaluation: synthetic scenario metrics and scenario summaries.
- Demo: controlled latest-log retrieval, anonymization, processing, analysis, and terminal-style run output.

## Database Tables

The schema is defined in `sql/schema.sql` under the `analytics` schema.

Main tables:

```text
analytics.request_logs
analytics.app_logs
analytics.dataset_quality_metrics
analytics.request_ip_window_features
analytics.app_user_window_features
analytics.request_ip_anomaly_scores
analytics.request_ip_threat_scores
analytics.synthetic_scenario_scores
analytics.synthetic_scenario_metrics
analytics.demo_ingestion_state
```

## Testing and Checks

Run Python tests:

```bash
.venv/bin/python -m pytest -q
```

Check Python syntax:

```bash
.venv/bin/python -m compileall backend src scripts
```

Build frontend:

```bash
npm --prefix frontend run build
```

## Common Problems

If the backend raises a database connection error, check `.env`, PostgreSQL status, and whether the database/user exist.

If the data-quality or loading scripts cannot find datasets, verify `config/datasets.yaml` and confirm that the anonymized JSONL files exist in `../app_engine_logs/anonymized/`.

If the dashboard loads but shows an API error, confirm the backend is running on port `8012` and that CORS allows the frontend origin.

If the dashboard has no results, run the pipeline in order: data quality, database load, feature build, model training, threat scoring, evaluation.

## Generated Artifacts

The project intentionally keeps generated thesis artifacts:

- trained model files in `models/`;
- markdown summaries in `reports/summaries/`;
- CSV tables in `reports/tables/`;
- figures in `reports/figures/`;
- production frontend output in `frontend/dist/` when built.

Do not delete these unless you are intentionally regenerating them.
