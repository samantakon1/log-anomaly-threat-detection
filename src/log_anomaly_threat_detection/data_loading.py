from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def workspace_root() -> Path:
    return project_root().parent


def resolve_project_path(path: str | Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return (project_root() / candidate).resolve()


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    resolved = resolve_project_path(path)
    rows: list[dict[str, Any]] = []
    with resolved.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number} in {resolved}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"Expected JSON object on line {line_number} in {resolved}")
            rows.append(value)
    return rows


def load_dataset_config(path: str | Path = "config/datasets.yaml") -> dict[str, dict[str, str]]:
    """Load the small datasets.yaml file without requiring PyYAML at this stage."""
    resolved = resolve_project_path(path)
    datasets: dict[str, dict[str, str]] = {}
    current_name: str | None = None

    for raw_line in resolved.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if indent == 2 and line.endswith(":"):
            current_name = line[:-1]
            datasets[current_name] = {}
        elif indent == 4 and current_name and ":" in line:
            key, value = line.split(":", 1)
            datasets[current_name][key.strip()] = value.strip()

    if not datasets:
        raise ValueError(f"No datasets found in {resolved}")
    return datasets
