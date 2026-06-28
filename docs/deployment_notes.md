# Dashboard Deployment Notes

The dashboard is designed as two separate services:

| Layer | Technology | Role |
| --- | --- | --- |
| Backend API | FastAPI | Reads processed/anonymized PostgreSQL tables and exposes safe dashboard endpoints. |
| Frontend | React + Vite | Displays analyst-facing overview, alert review, incident, and evaluation views. |
| Database | PostgreSQL | Stores anonymized logs, engineered features, anomaly scores, threat scores, and synthetic evaluation outputs. |

## Backend Configuration

The backend uses the same database configuration as the processing scripts. The preferred local configuration is stored in `.env`:

```text
DB_HOST=localhost
DB_PORT=5432
DB_NAME=log_anomaly_threat_detection
DB_USER=log_anomaly_app
DB_PASSWORD=...
```

The backend must not be deployed with raw private log files. It only needs access to the processed PostgreSQL tables under the `analytics` schema.

## Frontend Configuration

The frontend reads the API base URL from:

```text
VITE_API_BASE_URL
```

For local development, it defaults to:

```text
http://127.0.0.1:8012
```

For deployment, set `VITE_API_BASE_URL` to the deployed backend URL before building the frontend.

## Build Commands

Backend syntax check:

```bash
.venv/bin/python -m compileall backend src
```

Frontend production build:

```bash
npm --prefix frontend run build
```

## Deployment Boundary

The dashboard is a demonstration and review interface for the thesis framework. It is not a production SIEM, not an autonomous blocking system, and not a replacement for incident-response procedures.
