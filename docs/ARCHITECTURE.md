# Architecture and implementation status

The design follows `docs/analysis/FINAL_ARCHITECTURE.md`. Where this implementation deliberately differs from that document, the difference is listed in the last section.

Status legend:
- **Implemented**: code and tests exist and pass.
- **Planned**: not started.
- **Experimental**: implemented but not yet validated.
- **Not evaluated**: no experiment has been run yet.

## Module status (after Milestone 1)

| Module (`backend/hqc/…`) | Responsibility | Status | Milestone |
|---|---|---|---|
| `common/schemas/` | Typed data contracts for all stages | **Implemented** | 1 |
| `common/errors.py` | Exception hierarchy (invalid technique, missing dataset, feature-schema mismatch, missing checkpoint, unsupported ATT&CK version, invalid event, quantum backend unavailable, leakage, storage) | **Implemented** | 1 |
| `common/logging.py` | Structured JSON logging with secret redaction | **Implemented** | 1 |
| `common/repro.py` | Seeding, environment capture, git commit lookup | **Implemented** | 1 |
| `config/` | YAML defaults + `.env` + environment overrides; ATT&CK version validation | **Implemented** | 1 |
| `storage/` | `Store` protocol + `SQLiteStore` (stdlib `sqlite3`); evaluation runs are write-once | **Implemented** | 1 |
| `api/` | FastAPI app factory, `GET /health` | **Implemented** (health only) | 1 / 8 |
| `mitre/` | ATT&CK knowledge base, Attack Flow parser, mapping | Planned | 2 |
| `prediction/` | Vocabulary, Markov, LSTM, fusion, beam search | Planned | 2–4 |
| `ingestion/`, `preprocessing/`, `detection/` | Dataset adapters, train-only pipelines, classical detection | Planned | 5 |
| `quantum/`, `fusion/` | QuantumGate, ZZ quantum-kernel second opinion, controls, disagreement signal | Planned | 6 |
| `attack_chain/`, `risk/`, `defense/` | Reconstruction, explainable risk, recommendation-only defense | Planned (defense guardrail test already active) | 7 |
| `frontend/` | React + Vite + TypeScript SOC dashboard | Planned | 9 |

## Data contracts (`hqc.common.schemas`)

| Contract | Notes |
|---|---|
| `SecurityEvent` | Discriminated union on `event_type`: `NetworkFlow`, `AuthenticationEvent`, `SystemEvent`, `APIEvent`. Timestamps must be timezone-aware and are normalised to UTC. Flow features must be finite. Every event carries `data_origin` (REAL / SYNTHETIC). `ground_truth_label` is for evaluation only |
| `DetectionResult` + `QuantumOpinion` | Holds the classical verdict and an optional quantum opinion. `needs_additional_evidence` is true on disagreement, and the classical verdict is never overridden |
| `ATTACKTechnique` | Technique-ID format and parent/sub-technique consistency are validated |
| `TechniqueCandidate` | Mapping output: one or more candidates, each with confidence and evidence |
| `AttackStep` | Provenance is `OBSERVED` (requires `event_id`), `INFERRED` or `PREDICTED` |
| `AttackChain` | Order is preserved. Out-of-order timestamps are **rejected, never sorted**. Predicted steps are not allowed in a chain |
| `PredictionResult` | Next-step distribution (sum ≤ 1, no duplicates, sorted) and paths (length and horizon checked). `provenance` is fixed to `PREDICTED` |
| `RiskAssessment` | 0–100 score with required explainable components. Fixed label `MODEL-DERIVED RISK SCORE` |
| `DefenseRecommendation` | The seven action categories; `requires_human_approval` is the literal `true` |
| `EvaluationResult` | Full run metadata. **Rejects overlapping train/test sources**. Metrics must be present if and only if the status is `EVALUATED` |

All contracts forbid unknown fields (`extra="forbid"`) and round-trip through JSON (tested).

## Differences from `docs/analysis/FINAL_ARCHITECTURE.md`
- **Package names:** this build uses `config/` and `common/` instead of `core/`, following the master implementation prompt. The schemas live in `common/schemas/`.
- **Pipeline orchestrator:** not created as a separate `pipeline/` package yet. It will be added when there are stages to orchestrate (Milestone 7/10).
- **Storage:** the analysis proposed SQLAlchemy. The MVP uses stdlib `sqlite3` behind a `Store` protocol, which avoids a dependency. The protocol allows swapping later.
- **ATT&CK version:** the analysis left the choice between v16.x and latest open. The configured default is now the user's planned **19.2**, which is **unverified** until Milestone 2 checks the official release (see `DATASETS.md`).
