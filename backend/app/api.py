from __future__ import annotations

from fastapi import APIRouter, Query

from log_anomaly_threat_detection.dashboard_data import (
    DashboardFilters,
    get_alerts,
    get_evaluation_summary,
    get_incident_summary,
    get_overview,
    get_timeline,
)

from .schemas import AlertResponse, EvaluationResponse, IncidentResponse, OverviewResponse, TimelinePoint
from .demo_runner import demo_runs


router = APIRouter(prefix="/api")


@router.get("/overview", response_model=OverviewResponse)
def overview(model_version: str | None = None) -> dict:
    return get_overview(model_version=model_version)


@router.get("/alerts", response_model=list[AlertResponse])
def alerts(
    model_version: str | None = None,
    threat_level: str | None = Query(default=None, pattern="^(critical|high|medium|low)$"),
    security_relevant: bool | None = None,
    ip_hash: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict]:
    filters = DashboardFilters(
        model_version=model_version,
        threat_level=threat_level,
        security_relevant=security_relevant,
        ip_hash=ip_hash,
        limit=limit,
    )
    return get_alerts(filters)


@router.get("/timeline", response_model=list[TimelinePoint])
def timeline(model_version: str | None = None) -> list[dict]:
    return get_timeline(model_version=model_version)


@router.get("/evaluation", response_model=EvaluationResponse)
def evaluation() -> dict:
    return get_evaluation_summary()


@router.get("/incident", response_model=IncidentResponse)
def incident(model_version: str | None = None) -> dict:
    return get_incident_summary(model_version=model_version)


@router.post("/demo/get-process-latest")
def demo_get_process_latest() -> dict:
    return demo_runs.start("get_process_latest")


@router.post("/demo/analyse-latest")
def demo_analyse_latest() -> dict:
    return demo_runs.start("analyse_latest")


@router.get("/demo/status")
def demo_status() -> dict:
    return demo_runs.snapshot()
