# Versioned API (Milestone 8)

**Status:** implemented. It exposes the Milestone 7 services over HTTP and tests them with FastAPI's `TestClient`.

It is a defensive, **RECOMMENDATION-ONLY** research API:
- No endpoint executes, schedules or forwards any action.
- Recommendations are read with `GET` and always require human approval.
- Analyst decisions are `POST`ed, stored **append-only** and never executed. Every decision response carries `"executed": false`.
- Risk scores are **MODEL-DERIVED**. No quantum advantage is claimed.
- CIC-IDS2017 labels are not mapped to ATT&CK techniques.

```bash
uvicorn hqc.api.server:create_api_app --factory --host 127.0.0.1 --port 8000   # localhost only
# interactive schema: http://127.0.0.1:8000/docs
```

**Two factories:**
- `hqc.api.server:create_api_app` serves `/health` and `/api/v1`.
- The Milestone 1 factory `hqc.api.app:create_app` (health only) is unchanged.

**Dependencies:**
- The intelligence services load lazily on first use. They need the local ATT&CK 19.2 knowledge base and the stored Milestone 3/4 model artifacts. **Nothing is retrained.**
- If those are missing, the `/api/v1` service endpoints return **503** with no filesystem paths. `/health` and `/api/v1/runs` still work.

## Endpoints
Only `GET` and `POST` exist; there is no PUT, PATCH or DELETE (tested).

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness (Milestone 1) |
| GET | `/api/v1/meta` | ATT&CK and vocabulary versions; prediction model versions (M3 B1/M1, M4 LSTM fold-00, hybrid α=0.7); evidence, correlation, risk and defense policy versions; safety contract |
| GET | `/api/v1/scenarios/synthetic` | The **SYNTHETIC** integration scenario (hand-authored) |
| POST | `/api/v1/chains/reconstruct` | `{observations, as_of?}` → `ChainReconstruction`: incident chains in arrival order (never sorted), unmapped events, correlation decisions |
| POST | `/api/v1/predictions` | `{chain, as_of?}` → next-step probabilities, beam path scores (PREDICTED, uncalibrated) and P(next technique is Exfiltration/Impact) |
| POST | `/api/v1/risk/assess` | `{chain, prediction?, high_impact_next_step_probability?, resources?, as_of?}` → `RiskAssessment` (MODEL-DERIVED; quantum weight 0) |
| POST | `/api/v1/assessments` | `{observations, resources?, as_of?}` → full pipeline output, **stored immutably**; returns `201` with `assessment_id` |
| GET | `/api/v1/assessments` | Summaries (`limit` 1–200, `offset`) |
| GET | `/api/v1/assessments/{assessment_id}` | Stored assessment |
| GET | `/api/v1/assessments/{id}/recommendations` | Recommendations, each with its decision history and `executed: false` |
| GET | `/api/v1/assessments/{id}/recommendations/{recommendation_id}` | One recommendation |
| GET | `/api/v1/assessments/{id}/recommendations/{rid}/decisions` | Decision audit history |
| POST | `/api/v1/assessments/{id}/recommendations/{rid}/decisions` | Append `{decision: ACKNOWLEDGED|APPROVED|REJECTED, analyst, note?}`. **Recorded only**; returns `201`, `executed: false` |
| GET | `/api/v1/runs` | Stored evaluation runs (summaries only) |
| GET | `/api/v1/runs/{run_id}` | One run summary |

**Request types** are the typed Milestone 7 contracts (`Observation`, `IncidentChain`, `NextTechniquePrediction`, `ResourceContext`). Unknown fields are rejected.

**Limits:** at most 1,000 observations and 1,000 resources per request; analyst names up to 200 characters; notes up to 2,000.

## Safety rules (enforced in code and tests)
**Recommendations and decisions:**
- Recommendations have no write route.
- A stored recommendation's status stays `PROPOSED`; the decision history is separate.
- **Two-step approval:** `APPROVED` on a HIGH-disruption recommendation (isolate, disable credentials) is rejected with **409** unless an earlier `ACKNOWLEDGED` decision exists.
- **Append-only storage:** decisions and assessments live in API-owned SQLite tables (`api_decisions`, `api_assessments`, in `data/hqc_api.sqlite3`, which is git-ignored). SQLite triggers abort every UPDATE and DELETE.

**Evidence rules (same as Milestone 7):**
- Out-of-order evidence (`ChainOrderError`), tactic/technique mismatches and dataset labels used as technique IDs (e.g. `PortScan`) are rejected with **422**.
- Quantum disagreement never raises risk and withholds disruptive recommendations.

**Exposure:**
- No static-file mounts.
- CORS is restricted to configured origins, with GET/POST only and no wildcard.
- Run summaries omit internal paths, environment and configuration.

**Guardrail tests** (`tests/guardrails/test_api_safety.py`):
- The defense scanner is applied to every `hqc.api` module. It fails on process, shell, network-client, remote-execution, firewall, account and cloud modules, on `os.system`-style calls, `eval`/`exec`/`open`, and command-like literals. Only `sqlite3` and `threading` are allowed in addition.
- The route contract is checked: GET/POST only, recommendations GET-only, and no action-named routes.

## Example
```bash
curl -s localhost:8000/api/v1/meta
curl -s -X POST localhost:8000/api/v1/assessments -H 'Content-Type: application/json' -d @assessment.json
curl -s localhost:8000/api/v1/assessments/<id>/recommendations
curl -s -X POST localhost:8000/api/v1/assessments/<id>/recommendations/<rid>/decisions \
     -H 'Content-Type: application/json' -d '{"decision": "ACKNOWLEDGED", "analyst": "analyst-1"}'
```

## Limitations
- **No authentication or authorisation yet.** Analyst identity is a free-text field, not verified.
- Run the API on localhost only until authentication exists.
- No rate limiting, no streaming or replay ingestion, no pagination cursors. Assessments are synchronous.
- The API serves the same models and policies as Milestone 7. Their limitations are in `ATTACK_CHAIN_INTEGRATION.md`, `RISK_ENGINE.md` and `ADAPTIVE_DEFENSE.md`.
- The React dashboard (Milestone 9) is not built.
