from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import threading
import uuid

from log_anomaly_threat_detection.data_loading import project_root, workspace_root
from log_anomaly_threat_detection.database import apply_schema, connect


DEMO_SOURCE_NAME = "app_engine_request_logs"


@dataclass
class DemoRunState:
    run_id: str | None = None
    action: str | None = None
    status: str = "idle"
    started_at: str | None = None
    finished_at: str | None = None
    lines: list[str] = field(default_factory=list)
    error: str | None = None


class DemoRunManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state = DemoRunState()
        self._worker: threading.Thread | None = None

    def snapshot(self) -> dict:
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> dict:
        return {
            "run_id": self._state.run_id,
            "action": self._state.action,
            "status": self._state.status,
            "started_at": self._state.started_at,
            "finished_at": self._state.finished_at,
            "lines": list(self._state.lines),
            "error": self._state.error,
        }

    def start(self, action: str) -> dict:
        with self._lock:
            if self._state.status == "running":
                return self._snapshot_locked()

            self._state = DemoRunState(
                run_id=uuid.uuid4().hex,
                action=action,
                status="running",
                started_at=datetime.now(UTC).isoformat(),
                lines=[],
            )
            self._worker = threading.Thread(target=self._run_action, args=(action,), daemon=True)
            self._worker.start()
            return self._snapshot_locked()

    def _append(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._state.lines.append(f"[{timestamp}] {message}")

    def _finish(self, status: str, error: str | None = None) -> None:
        with self._lock:
            self._state.status = status
            self._state.error = error
            self._state.finished_at = datetime.now(UTC).isoformat()

    def _run_action(self, action: str) -> None:
        try:
            if action == "get_process_latest":
                self._get_and_process_latest_logs()
            elif action == "analyse_latest":
                self._analyse_latest_logs()
            else:
                raise ValueError(f"Unknown demo action: {action}")
        except Exception as exc:
            self._append(f"ERROR: {exc}")
            self._finish("failed", str(exc))
            return

        self._finish("completed")

    def _run_command(self, command: list[str], success_message: str | None = None) -> subprocess.CompletedProcess[str]:
        self._append(f"Running: {' '.join(command)}")
        completed = subprocess.run(
            command,
            cwd=project_root(),
            text=True,
            capture_output=True,
            check=False,
        )
        for line in completed.stdout.splitlines():
            self._append(line)
        for line in completed.stderr.splitlines():
            self._append(f"ERROR: {line}")
        if completed.returncode != 0:
            raise RuntimeError(f"Command failed with exit code {completed.returncode}: {command[0]}")
        if success_message:
            self._append(success_message)
        return completed

    def _get_and_process_latest_logs(self) -> None:
        self._append("Starting latest App Engine log retrieval.")
        if shutil.which("gcloud") is None:
            raise RuntimeError("gcloud CLI was not found. Install/authenticate gcloud before running latest-log retrieval.")
        apply_schema()

        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        workspace = workspace_root()
        raw_path = workspace / "app_engine_logs/raw_private" / f"demo_latest_request_logs_{timestamp}.json"
        anonymized_path = workspace / "app_engine_logs/anonymized" / f"demo_latest_request_logs_{timestamp}.jsonl"
        generalized_path = workspace / "app_engine_logs/anonymized" / f"demo_latest_request_logs_{timestamp}.generalized.jsonl"
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        anonymized_path.parent.mkdir(parents=True, exist_ok=True)

        limit = os.environ.get("DEMO_LOG_LIMIT", "1000")
        base_filter = os.environ.get(
            "DEMO_LOG_FILTER",
            'resource.type="gae_app" AND protoPayload.@type="type.googleapis.com/google.appengine.logging.v1.RequestLog"',
        )
        start_timestamp = self._next_fetch_start_timestamp()
        if start_timestamp:
            start_text = start_timestamp.isoformat().replace("+00:00", "Z")
            log_filter = f'({base_filter}) AND timestamp >= "{start_text}"'
            self._append(f"Fetching logs from stored high-water mark with overlap: {start_text}")
        else:
            freshness = os.environ.get("DEMO_LOG_FRESHNESS", "1h")
            log_filter = base_filter
            self._append(f"No previous fetch timestamp found. Fetching recent logs with freshness {freshness}.")

        command = [
            "gcloud",
            "logging",
            "read",
            log_filter,
            f"--limit={limit}",
            "--order=asc",
            "--format=json",
        ]
        if not start_timestamp:
            command.insert(4, f"--freshness={os.environ.get('DEMO_LOG_FRESHNESS', '1h')}")
        project_id = os.environ.get("DEMO_GCLOUD_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
        if project_id:
            command.append(f"--project={project_id}")

        self._append("Connecting to App Engine logging through gcloud.")
        completed = subprocess.run(command, cwd=workspace, text=True, capture_output=True, check=False)
        for line in completed.stderr.splitlines():
            self._append(f"ERROR: {line}")
        if completed.returncode != 0:
            raise RuntimeError(f"gcloud logging read failed with exit code {completed.returncode}.")

        try:
            entries = json.loads(completed.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise RuntimeError("gcloud returned output that was not valid JSON.") from exc
        if not isinstance(entries, list):
            raise RuntimeError("gcloud returned an unexpected log payload.")

        raw_path.write_text(json.dumps(entries, ensure_ascii=True, indent=2), encoding="utf-8")
        self._append(f"Successfully connected to App Engine. Retrieved {len(entries):,} request-log rows.")
        self._append(f"Raw private export saved outside project reports: {raw_path.relative_to(workspace)}")

        anonymizer = workspace / "scripts/anonymize_app_engine_logs.py"
        generalizer = workspace / "scripts/generalize_anonymized_paths.py"
        self._run_command(
            [sys.executable, str(anonymizer), str(raw_path), str(anonymized_path)],
            "Logs anonymized successfully.",
        )
        self._run_command(
            [sys.executable, str(generalizer), str(anonymized_path), str(generalized_path)],
            "Endpoint paths generalized successfully.",
        )
        self._run_command(
            [
                sys.executable,
                "scripts/load_anonymized_logs_to_db.py",
                "--request-path",
                str(generalized_path),
                "--request-dataset-name",
                "demo_latest_request_logs",
                "--skip-app-logs",
            ],
            "Latest anonymized logs loaded into PostgreSQL successfully.",
        )
        max_timestamp = self._max_entry_timestamp(entries)
        if max_timestamp:
            self._save_ingestion_state(max_timestamp, len(entries), raw_path.relative_to(workspace))
            self._append(f"Stored latest processed log timestamp: {max_timestamp.isoformat()}")
        else:
            self._append("No log timestamp found in this batch; ingestion high-water mark was not changed.")
        self._append("Get & Process latest logs completed.")

    def _analyse_latest_logs(self) -> None:
        self._append("Starting analysis of latest processed logs.")
        steps = [
            ([sys.executable, "scripts/build_features.py"], "Feature windows rebuilt successfully."),
            ([sys.executable, "scripts/train_baseline.py"], "Baseline anomaly model trained successfully."),
            ([sys.executable, "scripts/score_threats.py"], "Threat scoring completed successfully."),
            ([sys.executable, "scripts/run_evaluation.py"], "Synthetic evaluation refreshed successfully."),
        ]
        for command, success_message in steps:
            self._run_command(command, success_message)
        self._append("Analyse latest logs completed. Dashboard data can now be refreshed.")

    def _next_fetch_start_timestamp(self) -> datetime | None:
        sql = """
            SELECT last_log_timestamp
            FROM analytics.demo_ingestion_state
            WHERE source_name = %s
        """
        fallback_sql = "SELECT max(timestamp) FROM analytics.request_logs"
        with connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, (DEMO_SOURCE_NAME,))
                row = cursor.fetchone()
                value = row[0] if row else None
                if value is None:
                    cursor.execute(fallback_sql)
                    row = cursor.fetchone()
                    value = row[0] if row else None

        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)

        overlap_minutes = int(os.environ.get("DEMO_LOG_OVERLAP_MINUTES", "5"))
        return value.astimezone(UTC) - timedelta(minutes=overlap_minutes)

    def _max_entry_timestamp(self, entries: list[object]) -> datetime | None:
        timestamps: list[datetime] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            payload = entry.get("protoPayload") or {}
            raw_value = entry.get("timestamp") or payload.get("startTime")
            if not raw_value:
                continue
            try:
                parsed = datetime.fromisoformat(str(raw_value).replace("Z", "+00:00"))
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            timestamps.append(parsed.astimezone(UTC))
        return max(timestamps) if timestamps else None

    def _save_ingestion_state(self, max_timestamp: datetime, rows_retrieved: int, raw_path: Path) -> None:
        sql = """
            INSERT INTO analytics.demo_ingestion_state (
                source_name,
                last_log_timestamp,
                last_successful_run_id,
                last_successful_run_at,
                last_rows_retrieved,
                last_raw_path,
                updated_at
            )
            VALUES (%s, %s, %s, now(), %s, %s, now())
            ON CONFLICT (source_name) DO UPDATE SET
                last_log_timestamp = GREATEST(
                    COALESCE(analytics.demo_ingestion_state.last_log_timestamp, EXCLUDED.last_log_timestamp),
                    EXCLUDED.last_log_timestamp
                ),
                last_successful_run_id = EXCLUDED.last_successful_run_id,
                last_successful_run_at = EXCLUDED.last_successful_run_at,
                last_rows_retrieved = EXCLUDED.last_rows_retrieved,
                last_raw_path = EXCLUDED.last_raw_path,
                updated_at = now()
        """
        with self._lock:
            run_id = self._state.run_id
        with connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    sql,
                    (
                        DEMO_SOURCE_NAME,
                        max_timestamp,
                        run_id,
                        rows_retrieved,
                        str(raw_path),
                    ),
                )
            conn.commit()


demo_runs = DemoRunManager()
