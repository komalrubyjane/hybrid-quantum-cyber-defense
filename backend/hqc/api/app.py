"""FastAPI application factory.

Run locally::

    uvicorn hqc.api.app:create_app --factory --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from hqc import __version__
from hqc.api.routers import health
from hqc.common.logging import configure_logging, get_logger
from hqc.config import Settings, get_settings

log = get_logger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the API application.

    No static-file mounts and no wildcard CORS (both were issues in a reference repo).
    """
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)

    app = FastAPI(
        title="Hybrid Quantum-AI Cyber Defense (research prototype)",
        version=__version__,
        description="Defensive, recommendation-only research API.",
    )
    app.dependency_overrides[get_settings] = lambda: settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )
    app.include_router(health.router)
    log.info("api created", extra={"stage": "api", "environment": settings.environment})
    return app
