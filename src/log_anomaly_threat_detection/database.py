from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import psycopg
from psycopg import Connection
from psycopg.conninfo import make_conninfo

from log_anomaly_threat_detection.data_loading import project_root


def load_local_env() -> None:
    env_path = project_root() / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def database_url() -> str:
    load_local_env()
    password = os.environ.get("DB_PASSWORD")
    if password:
        return make_conninfo(
            host=os.environ.get("DB_HOST", "localhost"),
            port=os.environ.get("DB_PORT", "5432"),
            dbname=os.environ.get("DB_NAME", "log_anomaly_threat_detection"),
            user=os.environ.get("DB_USER", "log_anomaly_app"),
            password=password,
        )

    value = os.environ.get("DATABASE_URL")
    if value:
        return value

    raise RuntimeError(
        "Database connection is not set. Use DATABASE_URL or DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD in .env."
    )


def connect() -> Connection[Any]:
    return psycopg.connect(database_url())


def apply_schema(schema_path: str | Path = "sql/schema.sql") -> None:
    path = project_root() / schema_path
    sql = path.read_text(encoding="utf-8")
    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql)
        conn.commit()
