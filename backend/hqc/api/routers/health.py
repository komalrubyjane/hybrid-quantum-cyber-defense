"""Health-check endpoint."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends

from hqc import __version__
from hqc.common.schemas import SCHEMA_VERSION
from hqc.common.schemas.base import HQCModel, utc_now
from hqc.config import Settings, get_settings

router = APIRouter(tags=["health"])


class HealthResponse(HQCModel):
    status: Literal["ok"] = "ok"
    service: str = "hqc"
    version: str
    schema_version: str
    attack_version: str
    environment: str
    time: datetime
    defense_mode: Literal["recommendation-only"] = "recommendation-only"


@router.get("/health", response_model=HealthResponse)
def health(settings: Annotated[Settings, Depends(get_settings)]) -> HealthResponse:
    """Liveness check. Reports configuration labels only (no paths or secrets)."""
    return HealthResponse(
        version=__version__,
        schema_version=SCHEMA_VERSION,
        attack_version=settings.attack_version,
        environment=settings.environment,
        time=utc_now(),
    )
