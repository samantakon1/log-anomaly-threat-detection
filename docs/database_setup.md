# Database Setup Guide

This guide explains how to prepare a local PostgreSQL database for the `log-anomaly-threat-detection` project.

## 1. Confirm PostgreSQL Is Running

Run:

```bash
pg_isready
```

Expected result:

```text
/var/run/postgresql:5432 - accepting connections
```

This has already been checked on this machine.

## 2. Open PostgreSQL As The postgres User

On Ubuntu, open a terminal and run:

```bash
sudo -u postgres psql
```

If it opens successfully, you will see a prompt similar to:

```text
postgres=#
```

## 3. Create The Project Database

Inside the `psql` prompt, run:

```sql
CREATE DATABASE log_anomaly_threat_detection;
```

Then connect to it:

```sql
\c log_anomaly_threat_detection
```

## 4. Create A Project User

Use a local development password. Do not use a real private password in the thesis document.

```sql
CREATE USER log_anomaly_app WITH PASSWORD 'change_this_local_password';
```

Grant access:

```sql
GRANT CONNECT ON DATABASE log_anomaly_threat_detection TO log_anomaly_app;
GRANT CREATE ON DATABASE log_anomaly_threat_detection TO log_anomaly_app;
GRANT USAGE, CREATE ON SCHEMA public TO log_anomaly_app;
```

## 5. Create The Analytics Schema

Still inside the database, run:

```sql
CREATE SCHEMA IF NOT EXISTS analytics;
GRANT USAGE, CREATE ON SCHEMA analytics TO log_anomaly_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA analytics GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO log_anomaly_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA analytics GRANT USAGE, SELECT ON SEQUENCES TO log_anomaly_app;
```

## 6. Test The User Connection

Exit `psql`:

```sql
\q
```

Then test:

```bash
psql -h localhost -U log_anomaly_app -d log_anomaly_threat_detection
```

Enter the password when prompted.

If the connection works, run:

```sql
SELECT current_database(), current_user;
```

Then exit:

```sql
\q
```

## 7. Add The Connection To DBeaver

In DBeaver:

1. Click **New Database Connection**.
2. Choose **PostgreSQL**.
3. Use these settings:

```text
Host: localhost
Port: 5432
Database: log_anomaly_threat_detection
Username: log_anomaly_app
Password: change_this_local_password
```

4. Click **Test Connection**.
5. If the test succeeds, save the connection.

## 8. Environment Configuration For The Project

The backend and pipeline scripts read the PostgreSQL settings from `.env` or from environment variables.

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=log_anomaly_threat_detection
DB_USER=log_anomaly_app
DB_PASSWORD=change_this_local_password
```

`DATABASE_URL` is also supported:

```bash
export DATABASE_URL="postgresql://log_anomaly_app:change_this_local_password@localhost:5432/log_anomaly_threat_detection"
```

Do not commit real deployment passwords.

## 9. What Will Be Stored In The Database

The database stores processed outputs only:

- feature rows,
- anomaly scores,
- threat scores,
- alert reasons,
- dashboard summaries,
- evaluation results.

Do not store:

- raw private logs,
- real IP addresses,
- real user names,
- real tenant/client names,
- payloads,
- tokens,
- credentials.

## 10. Load The Project Schema And Anonymized Data

After the database and user are created, install the Python project dependencies if needed:

```bash
python3 -m pip install -e .
```

Then create a local `.env` file in the project folder:

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=log_anomaly_threat_detection
DB_USER=log_anomaly_app
DB_PASSWORD=change_this_local_password
```

This separate-field format is safer than `DATABASE_URL` if the password contains special URL characters such as `@`, `#`, `%`, `/`, or `:`.

From the project folder, create the schema and load the current generalized/anonymized datasets:

```bash
python3 scripts/load_anonymized_logs_to_db.py
```

This script creates the tables from:

```text
sql/schema.sql
```

Then it loads:

- 30-day generalized/anonymized request logs into `analytics.request_logs`
- 7-day generalized/anonymized structured application logs into `analytics.app_logs`
- generated quality CSV metrics into `analytics.dataset_quality_metrics`

To create only the schema without loading data:

```bash
python3 scripts/load_anonymized_logs_to_db.py --schema-only
```

The loader uses `request_hash` as a unique key, so running it again will not duplicate already-loaded log rows.

## 11. Check The Loaded Rows

Connect to the database:

```bash
psql -h localhost -U log_anomaly_app -d log_anomaly_threat_detection
```

Then run:

```sql
SELECT count(*) FROM analytics.request_logs;
SELECT count(*) FROM analytics.app_logs;
SELECT dataset, count(*) FROM analytics.dataset_quality_metrics GROUP BY dataset;
```

Expected counts for the current datasets are approximately:

```text
request_logs: 50,000
app_logs: 9,623
```

## 12. How The Backend Connects

The reusable database helper is:

```text
src/log_anomaly_threat_detection/database.py
```

It loads the project `.env` file automatically, supports the separate `DB_*` settings and `DATABASE_URL`, and is used by the pipeline scripts and dashboard API routes.
