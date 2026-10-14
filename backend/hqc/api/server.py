"""Versioned API application (Milestone 8): ``/health`` plus ``/api/v1``.

Run locally (binds to localhost by default)::

    uvicorn hqc.api.server:create_api_app --factory --host 127.0.0.1 --port 8000

The Milestone 1 factory ``hqc.api.app:create_app`` (health only) is unchanged. This factory
adds the versioned intelligence API with the same safety settings: no static-file mounts, no
wildcard CORS, GET/POST only. RECOMMENDATION ONLY: no endpoint executes any action.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from hqc import __version__
from hqc.api.routers import health
from hqc.api.v1 import routes
from hqc.api.v1.services import ApiServices, ServiceProvider, ServicesUnavailableError
from hqc.api.v1.state import ApiStateStore
from hqc.common.logging import configure_logging, get_logger
from hqc.config import Settings, get_settings
from hqc.storage import SQLiteStore, Store

log = get_logger(__name__)
API_STATE_DB = "hqc_api.sqlite3"


def create_api_app(
    settings: Settings | None = None,
    services: ApiServices | None = None,
    state: ApiStateStore | None = None,
    evaluation_store: Store | None = None,
) -> FastAPI:
    """Build the versioned API. Arguments are injectable for tests."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)
    db_path = settings.resolve(settings.db_path)
    app = FastAPI(
        title="Hybrid Quantum-AI Cyber Defense API (research prototype)",
        version=__version__,
        description=(
            "Defensive, RECOMMENDATION-ONLY research API. Recommendations are read-only and "
            "always require human approval; analyst decisions are recorded, never executed. "
            "Risk scores are MODEL-DERIVED. No quantum advantage is claimed."
        ),
    )
    app.dependency_overrides[get_settings] = lambda: settings
    app.state.services = ServiceProvider(settings, services)
    app.state.api_state = state or ApiStateStore(db_path.with_name(API_STATE_DB))
    app.state.evaluation_store = evaluation_store or SQLiteStore(db_path)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @app.exception_handler(ServicesUnavailableError)
    def _unavailable(_: Request, exc: ServicesUnavailableError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)}
        )

    app.include_router(health.router)
    app.include_router(routes.router)
    log.info("versioned api created", extra={"stage": "api", "environment": settings.environment})
    return app
