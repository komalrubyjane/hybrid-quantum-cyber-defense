"""Health endpoint and API safety basics."""

from __future__ import annotations

from fastapi.testclient import TestClient

from hqc.api.app import create_app
from hqc.config import Settings


def test_health_ok(settings: Settings) -> None:
    client = TestClient(create_app(settings))
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["attack_version"] == settings.attack_version
    assert body["environment"] == "test"
    assert body["defense_mode"] == "recommendation-only"
    # No filesystem paths or secrets leak through the health check.
    assert not any("/" in str(v) for k, v in body.items() if k != "time")


def test_no_static_file_mount_or_unexpected_routes(settings: Settings) -> None:
    app = create_app(settings)
    # The OpenAPI path list is the public route contract (FastAPI may wrap routers).
    assert set(app.openapi()["paths"]) == {"/health"}
    client = TestClient(app)
    for probe in ("/static/.env", "/.env", "/output/results.json", "/pyproject.toml"):
        assert client.get(probe).status_code == 404


def test_cors_restricted_to_configured_origins(settings: Settings) -> None:
    client = TestClient(create_app(settings))
    allowed = client.options(
        "/health",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
    denied = client.options(
        "/health",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in denied.headers
