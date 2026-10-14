"""Export the Milestone 8 API contract and fixtures for the Milestone 9 dashboard.

Writes (no backend behaviour is changed; nothing is trained, evaluated or tracked):
- ``frontend/src/api/openapi.json``: the exact OpenAPI document of ``create_api_app``
  (the TypeScript types are generated from it: ``npm run gen:api``);
- ``frontend/src/fixtures/synthetic-assessment-request.json``: an ``AssessmentRequest`` built
  from the SYNTHETIC M7 scenario by the backend's own code (so the browser never re-implements
  the evidence / disagreement rules);
- with ``--responses`` (needs the local KB and stored artifacts): real API responses captured
  with in-memory API state, used as frontend test fixtures (``frontend/src/test/fixtures``).

Usage:
    python scripts/export_frontend_contract.py [--responses]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from hqc.api.server import create_api_app
from hqc.api.v1.state import ApiStateStore
from hqc.attack_chain.evidence import EvidencePolicy
from hqc.common.schemas.intelligence import EvidenceStatus, Observation
from hqc.config import PROJECT_ROOT, Settings, get_settings
from hqc.pipeline.config import build_pipeline, load_integration_config
from hqc.pipeline.scenario import build_observations, load_scenario
from hqc.storage import SQLiteStore

FRONTEND = PROJECT_ROOT / "frontend" / "src"


def _write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(PROJECT_ROOT)}")


def openapi_document() -> dict[str, Any]:
    settings = Settings(_env_file=None, environment="test")
    with SQLiteStore(":memory:") as runs:
        app = create_api_app(settings, state=ApiStateStore(":memory:"), evaluation_store=runs)
        spec: dict[str, Any] = app.openapi()
    return spec


def synthetic_request(settings: Settings) -> tuple[dict[str, Any], list[Observation]]:
    config = load_integration_config(PROJECT_ROOT / "configs" / "integration.yaml")
    built = build_pipeline(config, settings, PROJECT_ROOT)
    scenario, _ = load_scenario(PROJECT_ROOT / config.scenario)
    observations = build_observations(scenario, built.catalog, EvidencePolicy())
    body = {
        "observations": [o.model_dump(mode="json") for o in observations],
        "resources": [r.model_dump(mode="json") for r in scenario.resources],
        "as_of": scenario.as_of.isoformat(),
    }
    return body, observations


def capture_responses(
    settings: Settings, body: dict[str, Any], observations: list[Observation]
) -> None:
    out = FRONTEND / "test" / "fixtures"
    project_db = settings.resolve(settings.db_path)
    with SQLiteStore(project_db) as runs:  # read-only use: list stored run summaries
        client = TestClient(
            create_api_app(settings, state=ApiStateStore(":memory:"), evaluation_store=runs)
        )
        _write(out / "health.json", client.get("/health").json())
        _write(out / "meta.json", client.get("/api/v1/meta").json())
        _write(out / "runs.json", client.get("/api/v1/runs").json())
        record = client.post("/api/v1/assessments", json=body).json()
        _write(out / "assessment.json", record)
        aid = record["assessment_id"]
        # Same scenario without quantum opinions: a CRITICAL chain whose disruptive
        # recommendations are not withheld (exercises the two-step approval in the UI tests).
        plain = []
        for o in observations:
            if o.detection is not None:
                d = o.detection.model_copy(
                    update={"quantum": None, "quantum_disagreement": False,
                            "evidence_status": EvidenceStatus.NO_SECOND_OPINION}
                )  # fmt: skip
                o = o.model_copy(update={"detection": d})
            plain.append(o.model_dump(mode="json"))
        record2 = client.post("/api/v1/assessments", json={**body, "observations": plain}).json()
        _write(out / "assessment-no-quantum.json", record2)
        aid2 = record2["assessment_id"]
        recs = client.get(f"/api/v1/assessments/{aid2}/recommendations").json()
        _write(out / "recommendations-no-quantum.json", recs)
        isolate = next(v for v in recs if v["recommendation"]["action"] == "isolate_affected_host")
        rid = isolate["recommendation"]["recommendation_id"]
        base = f"/api/v1/assessments/{aid2}/recommendations/{rid}"
        conflict = client.post(
            f"{base}/decisions", json={"decision": "APPROVED", "analyst": "analyst-1"}
        )
        _write(out / "error-409.json", {"status": conflict.status_code, "body": conflict.json()})
        ack = client.post(
            f"{base}/decisions", json={"decision": "ACKNOWLEDGED", "analyst": "analyst-1"}
        )
        _write(out / "decision-acknowledged.json", ack.json())
        approved = client.post(
            f"{base}/decisions", json={"decision": "APPROVED", "analyst": "analyst-1"}
        )
        _write(out / "decision-approved.json", approved.json())
        _write(
            out / "recommendations.json",
            client.get(f"/api/v1/assessments/{aid}/recommendations").json(),
        )
        _write(out / "assessments.json", client.get("/api/v1/assessments").json())
        invalid = client.post("/api/v1/assessments", json={"observations": []})
        _write(out / "error-422.json", {"status": invalid.status_code, "body": invalid.json()})
        missing = client.get("/api/v1/assessments/asm-missing")
        _write(out / "error-404.json", {"status": missing.status_code, "body": missing.json()})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--responses", action="store_true", help="also capture API responses")
    args = parser.parse_args()
    _write(FRONTEND / "api" / "openapi.json", openapi_document())
    settings = get_settings()
    body, observations = synthetic_request(settings)
    _write(FRONTEND / "fixtures" / "synthetic-assessment-request.json", body)
    if args.responses:
        capture_responses(settings, body, observations)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
