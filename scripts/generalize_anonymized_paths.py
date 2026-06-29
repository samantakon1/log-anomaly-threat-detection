#!/usr/bin/env python3
"""Add privacy-safer endpoint path features to anonymized JSONL logs."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".wav",
    ".mp3",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
}

SUSPICIOUS_PATH_PATTERNS = [
    ".env",
    ".git",
    ".ds_store",
    "wp-admin",
    "wp-login",
    "phpmyadmin",
    "backup",
    "dump",
    ".sql",
    "gitconfig",
    "database",
    "db.sql",
    "passwd",
    "shadow",
]

NUM_RE = re.compile(r"^\d+$")
UUID_TOKEN_RE = re.compile(r"^\{(?:uuid|num|hex|email)\}$")
LONG_TOKEN_RE = re.compile(r"^[a-fA-F0-9]{12,}$")
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+){1,}$")


def split_path(path: str | None) -> list[str]:
    if not path:
        return []
    return [segment for segment in str(path).split("/") if segment]


def has_static_extension(segment: str) -> bool:
    lower = segment.lower()
    return any(lower.endswith(ext) for ext in STATIC_EXTENSIONS)


def endpoint_group(path: str | None) -> str:
    segments = split_path(path)
    if not segments:
        return "root"
    first = segments[0].lower()
    if first == "api":
        return "api"
    if has_static_extension(segments[-1]):
        return "static_asset"
    if any(pattern in str(path).lower() for pattern in SUSPICIOUS_PATH_PATTERNS):
        return "suspicious_probe"
    if first in {"v1", "v2"}:
        return "versioned_api"
    return "application_route"


def generalize_segment(segment: str, index: int) -> str:
    lower = segment.lower()
    if UUID_TOKEN_RE.match(lower):
        return lower
    if NUM_RE.match(segment):
        return "{num}"
    if LONG_TOKEN_RE.match(segment):
        return "{hex}"
    if has_static_extension(segment):
        return "{static_file}"
    if index > 0 and SLUG_RE.match(lower):
        return "{slug}"
    if len(segment) > 30:
        return "{long_segment}"
    return lower


def path_template(path: str | None) -> str | None:
    segments = split_path(path)
    if not segments:
        return "/"
    generalized = [generalize_segment(segment, index) for index, segment in enumerate(segments)]
    return "/" + "/".join(generalized[:6])


def add_features(row: dict[str, Any]) -> dict[str, Any]:
    path = row.get("endpoint_path")
    segments = split_path(path)
    lower_path = str(path or "").lower()
    row["endpoint_group"] = endpoint_group(path)
    row["endpoint_template"] = path_template(path)
    row["path_depth"] = len(segments)
    row["path_length"] = len(str(path or ""))
    row["is_static_asset"] = bool(segments and has_static_extension(segments[-1]))
    row["has_suspicious_path_pattern"] = any(
        pattern in lower_path for pattern in SUSPICIOUS_PATH_PATTERNS
    )
    return row


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_jsonl", type=Path)
    parser.add_argument("output_jsonl", type=Path)
    args = parser.parse_args()

    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with args.input_jsonl.open(encoding="utf-8") as src, args.output_jsonl.open(
        "w", encoding="utf-8"
    ) as out:
        for line in src:
            if not line.strip():
                continue
            row = add_features(json.loads(line))
            out.write(json.dumps(row, ensure_ascii=True) + "\n")
            count += 1
    print(f"wrote {count} rows with generalized path features to {args.output_jsonl}")


if __name__ == "__main__":
    main()
