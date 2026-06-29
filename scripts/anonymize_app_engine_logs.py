#!/usr/bin/env python3
"""Convert App Engine request logs exported by gcloud into anonymized JSONL."""

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


SENSITIVE_QUERY_KEYS = {
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


def clean_path(resource: str | None) -> str | None:
    if not resource:
        return None
    parsed = urlsplit(resource)
    path = parsed.path or "/"
    path = EMAIL_RE.sub("{email}", path)
    path = UUID_RE.sub("{uuid}", path)
    path = HEX_RE.sub("{hex}", path)
    path = LONG_NUM_RE.sub("{num}", path)
    return path


def query_key_summary(resource: str | None) -> dict[str, Any]:
    if not resource:
        return {"query_key_count": 0, "has_sensitive_query_key": False}
    query = urlsplit(resource).query
    if not query:
        return {"query_key_count": 0, "has_sensitive_query_key": False}
    keys = []
    for part in query.split("&"):
        if not part:
            continue
        keys.append(part.split("=", 1)[0].lower())
    return {
        "query_key_count": len(keys),
        "has_sensitive_query_key": any(key in SENSITIVE_QUERY_KEYS for key in keys),
    }


def user_agent_category(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    ua = user_agent.lower()
    if any(marker in ua for marker in ("bot", "crawler", "spider", "slurp")):
        return "bot"
    if "mobile" in ua or "android" in ua or "iphone" in ua:
        return "mobile_browser"
    if "mozilla" in ua or "chrome" in ua or "safari" in ua or "firefox" in ua:
        return "desktop_browser"
    if "curl" in ua or "wget" in ua or "python-requests" in ua or "postman" in ua:
        return "script_or_api_client"
    return "other"


def latency_ms(value: Any) -> float | None:
    if value in (None, ""):
        return None
    text = str(value)
    if text.endswith("s"):
        text = text[:-1]
    try:
        return round(float(text) * 1000, 3)
    except ValueError:
        return None


def anonymize_entry(entry: dict[str, Any], salt: str) -> dict[str, Any]:
    payload = entry.get("protoPayload") or {}
    resource_labels = (entry.get("resource") or {}).get("labels") or {}
    resource = payload.get("resource")
    query_summary = query_key_summary(resource)

    status = payload.get("status", (entry.get("httpRequest") or {}).get("status"))
    try:
        status_int = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_int = None

    return {
        "timestamp": entry.get("timestamp") or payload.get("startTime"),
        "start_time": payload.get("startTime"),
        "end_time": payload.get("endTime"),
        "module_id": payload.get("moduleId") or resource_labels.get("module_id"),
        "version_id": payload.get("versionId") or resource_labels.get("version_id"),
        "method": payload.get("method"),
        "status_code": status_int,
        "status_family": f"{status_int // 100}xx" if status_int is not None else None,
        "latency_ms": latency_ms(payload.get("latency")),
        "response_size": payload.get("responseSize"),
        "endpoint_path": clean_path(resource),
        "query_key_count": query_summary["query_key_count"],
        "has_sensitive_query_key": query_summary["has_sensitive_query_key"],
        "host_hash": hash_value(payload.get("host"), salt),
        "ip_hash": hash_value(payload.get("ip"), salt),
        "user_agent_category": user_agent_category(payload.get("userAgent")),
        "user_agent_hash": hash_value(payload.get("userAgent"), salt),
        "url_map_entry": payload.get("urlMapEntry"),
        "finished": payload.get("finished"),
        "app_engine_release": payload.get("appEngineRelease"),
        "trace_hash": hash_value(payload.get("traceId") or entry.get("trace"), salt),
        "request_hash": hash_value(payload.get("requestId") or entry.get("insertId"), salt),
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

    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with args.output_jsonl.open("w", encoding="utf-8") as out:
        for entry in entries:
            out.write(json.dumps(anonymize_entry(entry, salt), ensure_ascii=True) + "\n")

    print(f"wrote {len(entries)} anonymized rows to {args.output_jsonl}")


if __name__ == "__main__":
    main()
