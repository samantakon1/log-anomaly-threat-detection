from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, ConfigDict


class DashboardBaseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class OverviewResponse(DashboardBaseModel):
    model_version: str
    total_windows: int
    high_anomaly_score_windows: int
    security_relevant_windows: int
    high_or_critical_windows: int
    avg_anomaly_score: float
    avg_threat_score: float
    first_window: datetime | None
    last_window: datetime | None
    threat_level_counts: dict[str, int]


class AlertResponse(DashboardBaseModel):
    window_start: datetime
    ip_hash: str
    model_version: str
    threat_score: float
    threat_level: str
    is_security_relevant: bool
    reasons: list[str]
    anomaly_score: float
    anomaly_rank: int
    request_count: int
    suspicious_path_count: int
    error_count: int
    error_rate: float
    unique_endpoint_count: int
    static_asset_count: int
    off_hours: bool
    module_id: str | None = None
    endpoint_template: str | None = None
    endpoint_group: str | None = None
    status_family: str | None = None


class TimelinePoint(DashboardBaseModel):
    bucket: datetime
    total_windows: int
    security_relevant_windows: int
    high_or_critical_windows: int
    max_threat_score: float
    max_anomaly_score: float


class MetricResponse(DashboardBaseModel):
    ranking_method: str
    metric_name: str
    k_value: int
    metric_value: float


class ScenarioResponse(DashboardBaseModel):
    scenario_name: str
    is_attack_like: bool
    rows: int
    avg_anomaly_score: float
    avg_threat_score: float
    security_relevant_rows: int


class EvaluationResponse(DashboardBaseModel):
    evaluation_id: str | None
    metrics: list[MetricResponse]
    scenarios: list[ScenarioResponse]


class IncidentResponse(DashboardBaseModel):
    model_version: str
    date: date
    interpretation: str
    windows: list[AlertResponse]
