#!/usr/bin/env python3
"""Convert structured App Engine application logs into anonymized JSONL.

This script intentionally skips unstructured textPayload entries. Raw text logs can
contain arbitrary sensitive values, so only jsonPayload records are converted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


SENSITIVE_KEYS = {
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "key",
    "apikey",
    "api_key",
    "password",
    "pass",
    "secret",
    "session",
    "sid",
    "authorization",
    "cookie",
    "email",
}

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
LONG_NUM_RE = re.compile(r"\b\d{4,}\b")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")
EMAIL_RE = re.compile(r"[^/@\s]+@[^/@\s]+\.[^/@\s]+")


def load_or_create_salt(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_hex(32)
    path.write_text(salt + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return salt


def hash_value(value: Any, salt: str) -> str | None:
    if value in (None, ""):
        return None
    digest = hashlib.sha256((salt + str(value)).encode("utf-8")).hexdigest()
    return digest[:16]


def clean_path(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlsplit(str(value))
    path = parsed.path or "/"
    path = EMAIL_RE.sub("{email}", path)
    path = UUID_RE.sub("{uuid}", path)
    path = HEX_RE.sub("{hex}", path)
    path = LONG_NUM_RE.sub("{num}", path)
    return path


def safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def nested_key_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"key_count": 0, "has_sensitive_key": False}
    keys = {str(key).lower() for key in value.keys()}
    return {
        "key_count": len(keys),
        "has_sensitive_key": any(key in SENSITIVE_KEYS for key in keys),
    }


def status_family(status: int | None) -> str | None:
    if status is None:
        return None
    return f"{status // 100}xx"


def anonymize_entry(entry: dict[str, Any], salt: str) -> dict[str, Any] | None:
    payload = entry.get("jsonPayload")
    if not isinstance(payload, dict):
        return None

    labels = (entry.get("resource") or {}).get("labels") or {}
    request_summary = nested_key_summary(payload.get("requestData"))
    response_summary = nested_key_summary(payload.get("responseData"))
    headers_summary = nested_key_summary(payload.get("headers"))
    status = safe_int(payload.get("status"))

    return {
        "timestamp": entry.get("timestamp") or payload.get("timestamp"),
        "receive_timestamp": entry.get("receiveTimestamp"),
        "module_id": labels.get("module_id"),
        "version_id": labels.get("version_id"),
        "level": payload.get("level"),
        "event": payload.get("event"),
        "method": payload.get("method"),
        "status_code": status,
        "status_family": status_family(status),
        "response_time_ms": safe_int(payload.get("responseTime")),
        "endpoint_path": clean_path(payload.get("url")),
        "user_id_hash": hash_value(payload.get("userId"), salt),
        "tenant_hash": hash_value(payload.get("shopId"), salt),
        "request_hash": hash_value(payload.get("requestId") or entry.get("insertId"), salt),
        "has_error": "error" in payload,
        "error_text_length": len(str(payload.get("error"))) if payload.get("error") is not None else 0,
        "request_data_key_count": request_summary["key_count"],
        "request_data_has_sensitive_key": request_summary["has_sensitive_key"],
        "response_data_key_count": response_summary["key_count"],
        "response_data_has_sensitive_key": response_summary["has_sensitive_key"],
        "headers_key_count": headers_summary["key_count"],
        "headers_has_sensitive_key": headers_summary["has_sensitive_key"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_json", type=Path)
    parser.add_argument("output_jsonl", type=Path)
    parser.add_argument(
        "--salt-file",
        type=Path,
        default=Path("app_engine_logs/raw_private/.anonymization_salt"),
    )
    args = parser.parse_args()

    salt = load_or_create_salt(args.salt_file)
    with args.input_json.open(encoding="utf-8") as fh:
        entries = json.load(fh)

    rows = [row for entry in entries if (row := anonymize_entry(entry, salt)) is not None]

    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with args.output_jsonl.open("w", encoding="utf-8") as out:
        for row in rows:
            out.write(json.dumps(row, ensure_ascii=True) + "\n")

    print(f"wrote {len(rows)} anonymized structured app-log rows to {args.output_jsonl}")


if __name__ == "__main__":
    main()
