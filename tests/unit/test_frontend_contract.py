"""The dashboard's API types are generated from frontend/src/api/openapi.json; it must equal the
live OpenAPI document of the Milestone 8 API (regenerate with
``python scripts/export_frontend_contract.py`` and ``npm run gen:api``)."""

from __future__ import annotations

import json
from typing import Any

from hqc.api.server import create_api_app
from hqc.api.v1.state import ApiStateStore
from hqc.config import PROJECT_ROOT, Settings
from hqc.storage import SQLiteStore

CONTRACT = PROJECT_ROOT / "frontend" / "src" / "api" / "openapi.json"


def openapi_document() -> dict[str, Any]:
    """Same construction as scripts/export_frontend_contract.py."""
    settings = Settings(_env_file=None, environment="test")  # type: ignore[call-arg]
    with SQLiteStore(":memory:") as runs:
        app = create_api_app(settings, state=ApiStateStore(":memory:"), evaluation_store=runs)
        spec: dict[str, Any] = app.openapi()
    return spec


def test_frontend_contract_matches_the_api() -> None:
    committed = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert committed == openapi_document(), "frontend API contract is stale; re-export it"


def test_contract_has_no_execution_routes() -> None:
    paths = json.loads(CONTRACT.read_text(encoding="utf-8"))["paths"]
    for path, methods in paths.items():
        assert set(methods) <= {"get", "post"}, path
        assert "execute" not in path and "apply" not in path
