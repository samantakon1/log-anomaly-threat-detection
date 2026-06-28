from __future__ import annotations

from collections.abc import Callable

import pandas as pd

from log_anomaly_threat_detection.anomaly_detection import REQUEST_FEATURE_COLUMNS, load_request_feature_frame


ScenarioMutator = Callable[[pd.Series], dict[str, object]]


def _bounded_count(value: int, request_count: int) -> int:
    return max(0, min(int(value), int(request_count)))


def endpoint_scanning(row: pd.Series) -> dict[str, object]:
    request_count = 220
    error_count = 200
    return {
        **row.to_dict(),
        "request_count": request_count,
        "unique_endpoint_count": 120,
        "unique_endpoint_group_count": 5,
        "unique_method_count": 2,
        "unique_user_agent_category_count": 1,
        "static_asset_count": 0,
        "suspicious_path_count": 45,
        "sensitive_query_count": 0,
        "status_2xx_count": 20,
        "status_3xx_count": 0,
        "status_4xx_count": 190,
        "status_5xx_count": 10,
        "error_count": error_count,
        "error_rate": error_count / request_count,
        "avg_latency_ms": 130.0,
        "p95_latency_ms": 360.0,
        "max_latency_ms": 1200.0,
        "avg_response_size": 900.0,
        "avg_endpoint_rarity": 7.5,
        "off_hours": False,
    }


def suspicious_probe_off_hours(row: pd.Series) -> dict[str, object]:
    request_count = 140
    error_count = 110
    return {
        **row.to_dict(),
        "request_count": request_count,
        "unique_endpoint_count": 70,
        "unique_endpoint_group_count": 5,
        "unique_method_count": 2,
        "unique_user_agent_category_count": 1,
        "static_asset_count": 0,
        "suspicious_path_count": 80,
        "sensitive_query_count": 1,
        "status_2xx_count": 25,
        "status_3xx_count": 5,
        "status_4xx_count": 105,
        "status_5xx_count": 5,
        "error_count": error_count,
        "error_rate": error_count / request_count,
        "avg_latency_ms": 160.0,
        "p95_latency_ms": 420.0,
        "max_latency_ms": 1500.0,
        "avg_response_size": 700.0,
        "avg_endpoint_rarity": 8.0,
        "off_hours": True,
    }


def request_burst_scan(row: pd.Series) -> dict[str, object]:
    request_count = 650
    error_count = 150
    return {
        **row.to_dict(),
        "request_count": request_count,
        "unique_endpoint_count": 90,
        "unique_endpoint_group_count": 4,
        "unique_method_count": 3,
        "unique_user_agent_category_count": 1,
        "static_asset_count": 20,
        "suspicious_path_count": 20,
        "sensitive_query_count": 0,
        "status_2xx_count": 480,
        "status_3xx_count": 20,
        "status_4xx_count": 145,
        "status_5xx_count": 5,
        "error_count": error_count,
        "error_rate": error_count / request_count,
        "avg_latency_ms": 180.0,
        "p95_latency_ms": 520.0,
        "max_latency_ms": 1800.0,
        "avg_response_size": 1200.0,
        "avg_endpoint_rarity": 6.5,
        "off_hours": False,
    }


def repeated_error_attempts(row: pd.Series) -> dict[str, object]:
    request_count = 180
    error_count = 160
    return {
        **row.to_dict(),
        "request_count": request_count,
        "unique_endpoint_count": 4,
        "unique_endpoint_group_count": 2,
        "unique_method_count": 1,
        "unique_user_agent_category_count": 1,
        "static_asset_count": 0,
        "suspicious_path_count": 0,
        "sensitive_query_count": 0,
        "status_2xx_count": 20,
        "status_3xx_count": 0,
        "status_4xx_count": 155,
        "status_5xx_count": 5,
        "error_count": error_count,
        "error_rate": error_count / request_count,
        "avg_latency_ms": 140.0,
        "p95_latency_ms": 380.0,
        "max_latency_ms": 1000.0,
        "avg_response_size": 650.0,
        "avg_endpoint_rarity": 4.0,
        "off_hours": False,
    }


def static_asset_burst(row: pd.Series) -> dict[str, object]:
    request_count = 700
    error_count = 3
    return {
        **row.to_dict(),
        "request_count": request_count,
        "unique_endpoint_count": 12,
        "unique_endpoint_group_count": 1,
        "unique_method_count": 1,
        "unique_user_agent_category_count": 1,
        "static_asset_count": 680,
        "suspicious_path_count": 0,
        "sensitive_query_count": 0,
        "status_2xx_count": 500,
        "status_3xx_count": 197,
        "status_4xx_count": 3,
        "status_5xx_count": 0,
        "error_count": error_count,
        "error_rate": error_count / request_count,
        "avg_latency_ms": 80.0,
        "p95_latency_ms": 210.0,
        "max_latency_ms": 600.0,
        "avg_response_size": 3500.0,
        "avg_endpoint_rarity": 1.0,
        "off_hours": False,
    }


def popular_endpoint_spike(row: pd.Series) -> dict[str, object]:
    request_count = 550
    return {
        **row.to_dict(),
        "request_count": request_count,
        "unique_endpoint_count": 3,
        "unique_endpoint_group_count": 2,
        "unique_method_count": 1,
        "unique_user_agent_category_count": 1,
        "static_asset_count": 0,
        "suspicious_path_count": 0,
        "sensitive_query_count": 0,
        "status_2xx_count": 520,
        "status_3xx_count": 30,
        "status_4xx_count": 0,
        "status_5xx_count": 0,
        "error_count": 0,
        "error_rate": 0.0,
        "avg_latency_ms": 120.0,
        "p95_latency_ms": 260.0,
        "max_latency_ms": 650.0,
        "avg_response_size": 1400.0,
        "avg_endpoint_rarity": 1.2,
        "off_hours": False,
    }


def slow_backend_no_security_signal(row: pd.Series) -> dict[str, object]:
    request_count = 50
    return {
        **row.to_dict(),
        "request_count": request_count,
        "unique_endpoint_count": 5,
        "unique_endpoint_group_count": 2,
        "unique_method_count": 1,
        "unique_user_agent_category_count": 1,
        "static_asset_count": 0,
        "suspicious_path_count": 0,
        "sensitive_query_count": 0,
        "status_2xx_count": 48,
        "status_3xx_count": 2,
        "status_4xx_count": 0,
        "status_5xx_count": 0,
        "error_count": 0,
        "error_rate": 0.0,
        "avg_latency_ms": 1600.0,
        "p95_latency_ms": 3200.0,
        "max_latency_ms": 8000.0,
        "avg_response_size": 1600.0,
        "avg_endpoint_rarity": 1.8,
        "off_hours": False,
    }


SCENARIOS: list[tuple[str, bool, ScenarioMutator]] = [
    ("endpoint_scanning", True, endpoint_scanning),
    ("suspicious_probe_off_hours", True, suspicious_probe_off_hours),
    ("request_burst_scan", True, request_burst_scan),
    ("repeated_error_attempts", True, repeated_error_attempts),
    ("static_asset_burst", False, static_asset_burst),
    ("popular_endpoint_spike", False, popular_endpoint_spike),
    ("slow_backend_no_security_signal", False, slow_backend_no_security_signal),
]


def base_rows_per_scenario(rows_per_scenario: int, random_state: int = 42) -> pd.DataFrame:
    frame = load_request_feature_frame()
    candidates = frame[
        (frame["suspicious_path_count"] == 0)
        & (frame["error_rate"] <= 0.05)
        & (frame["request_count"] >= 2)
    ].copy()
    if len(candidates) < rows_per_scenario:
        candidates = frame.copy()
    return candidates.sample(n=rows_per_scenario, replace=len(candidates) < rows_per_scenario, random_state=random_state)


def generate_synthetic_scenarios(rows_per_scenario: int = 100, random_state: int = 42) -> pd.DataFrame:
    base_rows = base_rows_per_scenario(rows_per_scenario, random_state=random_state).reset_index(drop=True)
    synthetic_rows = []
    for scenario_index, (scenario_name, is_attack_like, mutator) in enumerate(SCENARIOS, start=1):
        for row_index, (_, base_row) in enumerate(base_rows.iterrows(), start=1):
            mutated = mutator(base_row)
            request_count = int(mutated["request_count"])
            error_count = _bounded_count(int(mutated["error_count"]), request_count)
            suspicious_path_count = _bounded_count(int(mutated["suspicious_path_count"]), request_count)
            mutated["error_count"] = error_count
            mutated["suspicious_path_count"] = suspicious_path_count
            mutated["error_rate"] = error_count / request_count if request_count else 0.0
            mutated["synthetic_id"] = f"{scenario_index:02d}_{row_index:04d}_{scenario_name}"
            mutated["scenario_name"] = scenario_name
            mutated["is_attack_like"] = is_attack_like
            mutated["ip_hash"] = f"synthetic_{scenario_index:02d}_{row_index:04d}"
            synthetic_rows.append(mutated)

    columns = [
        "synthetic_id",
        "scenario_name",
        "is_attack_like",
        "ip_hash",
        *REQUEST_FEATURE_COLUMNS,
    ]
    return pd.DataFrame(synthetic_rows)[columns]
