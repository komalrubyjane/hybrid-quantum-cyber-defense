"""Milestone 8: versioned API over the Milestone 7 services (test pipeline; no data needed)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from factories import evaluation_result
from hqc.api.server import create_api_app
from hqc.api.v1.schemas import MAX_OBSERVATIONS, Decision
from hqc.api.v1.services import ApiServices, ServiceProvider
from hqc.api.v1.state import ApiStateStore
from hqc.common.schemas import EvidenceStatus, Observation
from hqc.config import Settings
from hqc.storage import Collection, SQLiteStore
from m7_fixtures import (
    SCENARIO_PATH,
    make_pipeline,
    make_vocabulary,
    scenario,
    scenario_observations,
)

EXPECTED_ROUTES = {
    "/health": {"get"},
    "/api/v1/meta": {"get"},
    "/api/v1/scenarios/synthetic": {"get"},
    "/api/v1/chains/reconstruct": {"post"},
    "/api/v1/predictions": {"post"},
    "/api/v1/risk/assess": {"post"},
    "/api/v1/assessments": {"get", "post"},
    "/api/v1/assessments/{assessment_id}": {"get"},
    "/api/v1/assessments/{assessment_id}/recommendations": {"get"},
    "/api/v1/assessments/{assessment_id}/recommendations/{recommendation_id}": {"get"},
    "/api/v1/assessments/{assessment_id}/recommendations/{recommendation_id}/decisions": {
        "get",
        "post",
    },
    "/api/v1/runs": {"get"},
    "/api/v1/runs/{run_id}": {"get"},
}


@pytest.fixture
def state() -> Iterator[ApiStateStore]:
    s = ApiStateStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def client(settings: Settings, state: ApiStateStore) -> Iterator[TestClient]:
    services = ApiServices(
        pipeline=make_pipeline(),
        attack_version="19.2",
        vocabulary_version=make_vocabulary().vocabulary_version,
        scenario_path=SCENARIO_PATH,
    )
    with SQLiteStore(":memory:") as runs:
        runs.put(Collection.EVALUATION_RUNS, evaluation_result(run_id="run-1"))
        app = create_api_app(settings, services=services, state=state, evaluation_store=runs)
        yield TestClient(app)


def observations_json(observations: list[Observation] | None = None) -> list[dict[str, Any]]:
    return [o.model_dump(mode="json") for o in (observations or scenario_observations())]


def resources_json() -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in scenario().resources]


def assessment_body(observations: list[Observation] | None = None) -> dict[str, Any]:
    return {
        "observations": observations_json(observations),
        "resources": resources_json(),
        "as_of": scenario().as_of.isoformat(),
    }


def without_quantum() -> list[Observation]:
    out = []
    for o in scenario_observations():
        if o.detection is not None:
            d = o.detection.model_copy(
                update={"quantum": None, "quantum_disagreement": False,
                        "evidence_status": EvidenceStatus.NO_SECOND_OPINION}
            )  # fmt: skip
            o = o.model_copy(update={"detection": d})
        out.append(o)
    return out


# --- contract and safety -----------------------------------------------------------------


def test_route_contract_is_get_post_only(client: TestClient) -> None:
    paths = client.app.openapi()["paths"]  # type: ignore[attr-defined]
    assert {p: set(m) for p, m in paths.items()} == EXPECTED_ROUTES
    for path, methods in EXPECTED_ROUTES.items():
        assert not methods & {"put", "patch", "delete"}
        if "recommendations" in path and not path.endswith("/decisions"):
            assert methods == {"get"}  # recommendations are read-only
        for word in ("execute", "apply", "isolate", "block", "disable", "run_action"):
            assert word not in path


def test_health_meta_and_scenario(client: TestClient) -> None:
    assert client.get("/health").json()["defense_mode"] == "recommendation-only"
    meta = client.get("/api/v1/meta").json()
    assert meta["api_version"] == "v1" and meta["defense_mode"] == "recommendation-only"
    assert meta["risk_label"] == "MODEL-DERIVED RISK SCORE"
    assert (
        "No quantum advantage" in meta["claim_policy"]
        and "not MITRE ATT&CK" in meta["cic_label_policy"]
    )
    assert meta["policy_versions"]["defense"] == "defense-policy-v1"
    sc = client.get("/api/v1/scenarios/synthetic").json()
    assert sc["data_origin"] == "SYNTHETIC" and sc["scenario_id"] == "synthetic-multistage"


def test_static_paths_and_cors(client: TestClient) -> None:
    for probe in ("/static/.env", "/.env", "/data/hqc.sqlite3", "/api/v1/../pyproject.toml"):
        assert client.get(probe).status_code == 404
    denied = client.options(
        "/api/v1/meta",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in denied.headers


# --- stateless service endpoints -----------------------------------------------------------


def test_reconstruct_endpoint(client: TestClient) -> None:
    r = client.post("/api/v1/chains/reconstruct", json={"observations": observations_json()})
    assert r.status_code == 200
    body = r.json()
    assert body["unmapped_event_ids"] == ["syn-ms-e02"]
    assert [c["status"] for c in body["chains"]] == ["CORRELATED", "STANDALONE"]
    assert all(s["provenance"] == "OBSERVED" for c in body["chains"] for s in c["chain"]["steps"])


def test_reconstruct_rejects_bad_input(client: TestClient) -> None:
    obs = observations_json()
    late = [obs[3], obs[0]]  # same host, second is older: never re-sorted
    r = client.post("/api/v1/chains/reconstruct", json={"observations": late})
    assert r.status_code == 422 and "not re-sorted" in r.json()["detail"]
    bad_tactic = observations_json()
    bad_tactic[0]["techniques"][0]["tactic_id"] = "TA0010"
    r = client.post("/api/v1/chains/reconstruct", json={"observations": bad_tactic})
    assert r.status_code == 422 and "not a tactic" in r.json()["detail"]
    assert client.post("/api/v1/chains/reconstruct", json={"observations": []}).status_code == 422
    assert (
        client.post("/api/v1/chains/reconstruct", json={"observations": obs, "x": 1}).status_code
        == 422
    )
    too_many = {"observations": [obs[0]] * (MAX_OBSERVATIONS + 1)}
    assert client.post("/api/v1/chains/reconstruct", json=too_many).status_code == 422
    cic_label = observations_json()
    cic_label[0]["techniques"][0]["technique_id"] = "PortScan"
    assert (
        client.post("/api/v1/chains/reconstruct", json={"observations": cic_label}).status_code
        == 422
    )


def test_prediction_and_risk_endpoints(client: TestClient) -> None:
    chains = client.post(
        "/api/v1/chains/reconstruct", json={"observations": observations_json()}
    ).json()
    chain = chains["chains"][0]
    p = client.post("/api/v1/predictions", json={"chain": chain})
    assert p.status_code == 200
    pred = p.json()
    assert pred["prediction"]["provenance"] == "PREDICTED"
    assert pred["prediction"]["result"]["provenance"] == "PREDICTED"
    assert pred["high_impact_tactics"] == ["TA0010", "TA0040"]
    assert 0.0 <= pred["high_impact_next_step_probability"] <= 1.0
    body = {
        "chain": chain,
        "prediction": pred["prediction"],
        "high_impact_next_step_probability": pred["high_impact_next_step_probability"],
        "resources": resources_json(),
        "as_of": scenario().as_of.isoformat(),
    }
    risk = client.post("/api/v1/risk/assess", json=body)
    assert risk.status_code == 200
    assert risk.json()["label"] == "MODEL-DERIVED RISK SCORE" and risk.json()["level"] == "CRITICAL"
    q = {c["name"]: c for c in risk.json()["components"]}["quantum_second_opinion"]
    assert q["weight"] == 0.0 and q["contribution"] == 0.0
    early = {**body, "as_of": "2026-01-15T08:00:00Z"}
    assert client.post("/api/v1/risk/assess", json=early).status_code == 422
    bad_chain = {**chain, "chain": {**chain["chain"], "steps": [
        {**chain["chain"]["steps"][0], "provenance": "PREDICTED", "event_id": None}]}}  # fmt: skip
    assert client.post("/api/v1/predictions", json={"chain": bad_chain}).status_code == 422


# --- assessments, recommendations and decisions -------------------------------------------


def test_assessment_lifecycle(client: TestClient) -> None:
    r = client.post("/api/v1/assessments", json=assessment_body())
    assert r.status_code == 201
    record = r.json()
    aid = record["assessment_id"]
    assert aid.startswith("asm-") and record["data_origin"] == "SYNTHETIC"
    assert "RECOMMENDATION ONLY" in record["notice"]
    main = record["output"]["incidents"][0]
    assert main["risk"]["evidence_status"] == "NEEDS ADDITIONAL EVIDENCE"
    actions = {rec["action"] for rec in main["recommendations"]}
    assert not actions & {
        "isolate_affected_host",
        "block_suspicious_access",
        "disable_compromised_credentials",
    }
    assert client.get(f"/api/v1/assessments/{aid}").json() == record
    summaries = client.get("/api/v1/assessments").json()
    assert summaries[0]["assessment_id"] == aid and summaries[0]["incidents"] == 2
    assert client.get("/api/v1/assessments?limit=0").status_code == 422
    assert client.get("/api/v1/assessments/asm-missing").status_code == 404
    recs = client.get(f"/api/v1/assessments/{aid}/recommendations").json()
    assert len(recs) == sum(len(i["recommendations"]) for i in record["output"]["incidents"])
    for view in recs:
        assert view["executed"] is False and view["latest_decision"] is None
        assert view["recommendation"]["requires_human_approval"] is True
        assert view["recommendation"]["status"] == "PROPOSED"
    bad = assessment_body()
    bad["observations"] = [bad["observations"][3], bad["observations"][0]]
    assert client.post("/api/v1/assessments", json=bad).status_code == 422


def test_decisions_are_recorded_never_executed(client: TestClient, state: ApiStateStore) -> None:
    aid = client.post("/api/v1/assessments", json=assessment_body(without_quantum())).json()[
        "assessment_id"
    ]
    recs = {v["recommendation"]["action"]: v["recommendation"]
            for v in client.get(f"/api/v1/assessments/{aid}/recommendations").json()}  # fmt: skip
    isolate = recs["isolate_affected_host"]  # CRITICAL chain without unresolved disagreement
    assert isolate["disruption"] == "HIGH"
    base = f"/api/v1/assessments/{aid}/recommendations/{isolate['recommendation_id']}"
    early = client.post(f"{base}/decisions", json={"decision": "APPROVED", "analyst": "a1"})
    assert early.status_code == 409  # two-step acknowledgement for HIGH disruption
    ack = client.post(f"{base}/decisions", json={"decision": "ACKNOWLEDGED", "analyst": "a1"})
    assert ack.status_code == 201
    ok = client.post(
        f"{base}/decisions", json={"decision": "APPROVED", "analyst": "a2", "note": "n"}
    )
    assert ok.status_code == 201
    record = ok.json()
    assert record["executed"] is False and "executes nothing" in record["notice"]
    history = client.get(f"{base}/decisions").json()
    assert [d["decision"] for d in history] == ["ACKNOWLEDGED", "APPROVED"]
    view = client.get(base).json()
    assert view["latest_decision"] == "APPROVED" and view["executed"] is False
    assert view["recommendation"]["status"] == "PROPOSED"  # the stored recommendation is unchanged
    monitor = recs["escalate_severity"]
    direct = client.post(
        f"/api/v1/assessments/{aid}/recommendations/{monitor['recommendation_id']}/decisions",
        json={"decision": "REJECTED", "analyst": "a3"},
    )
    assert direct.status_code == 201
    for bad in ({"decision": "EXECUTE", "analyst": "a"}, {"decision": "APPROVED"},
                {"decision": "APPROVED", "analyst": "a", "run": True}):  # fmt: skip
        assert client.post(f"{base}/decisions", json=bad).status_code == 422
    missing = f"/api/v1/assessments/{aid}/recommendations/nope/decisions"
    ack_body = {"decision": "ACKNOWLEDGED", "analyst": "a"}
    assert client.post(missing, json=ack_body).status_code == 404
    assert client.get(f"/api/v1/assessments/{aid}/recommendations/nope").status_code == 404
    assert (
        client.get(f"/api/v1/assessments/{aid}/recommendations/nope/decisions").status_code == 404
    )


def test_state_is_append_only(state: ApiStateStore, client: TestClient) -> None:
    client.post("/api/v1/assessments", json=assessment_body())
    conn = state._conn
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        conn.execute("UPDATE api_assessments SET payload = '{}'")
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        conn.execute("DELETE FROM api_assessments")
    aid = state.list_assessments(1, 0)[0].assessment_id
    state.add_decision(aid, "r", Decision.ACKNOWLEDGED, "a", None)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE api_decisions SET decision = 'APPROVED'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM api_decisions")


def test_runs_are_summaries_without_paths(client: TestClient) -> None:
    runs = client.get("/api/v1/runs").json()
    assert [r["run_id"] for r in runs] == ["run-1"]
    assert set(runs[0]) >= {"task", "status", "metrics", "data_origin"}
    assert "model_configuration" not in runs[0] and "environment" not in runs[0]
    assert client.get("/api/v1/runs/run-1").json()["run_id"] == "run-1"
    assert client.get("/api/v1/runs/missing").status_code == 404


def test_services_unavailable_is_503_without_paths(settings: Settings, tmp_path: Path) -> None:
    with SQLiteStore(":memory:") as runs:
        app = create_api_app(settings, state=ApiStateStore(":memory:"), evaluation_store=runs)
        app.state.services = ServiceProvider(settings, config_path=tmp_path / "missing.yaml")
        client = TestClient(app)
        r = client.get("/api/v1/meta")
        assert r.status_code == 503 and "unavailable" in r.json()["detail"]
        assert str(tmp_path) not in r.text and "/" not in r.json()["detail"].replace(
            "docs/API.md", ""
        )
        assert client.get("/health").status_code == 200
        assert client.get("/api/v1/runs").status_code == 200  # stored runs do not need the models


def test_default_factory_wires_file_stores(settings: Settings, tmp_path: Path) -> None:
    local = settings.model_copy(update={"db_path": tmp_path / "hqc.sqlite3"})
    app = create_api_app(local)
    assert (tmp_path / "hqc_api.sqlite3").is_file()
    assert TestClient(app).get("/api/v1/runs").json() == []
