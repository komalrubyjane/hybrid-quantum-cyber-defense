# Architecture and implementation status

The design follows `docs/analysis/FINAL_ARCHITECTURE.md`. Where this implementation deliberately differs from that document, the difference is listed in the last section.

Status legend:
- **Implemented**: code and tests exist and pass.
- **Planned**: not started.
- **Experimental**: implemented but not yet validated.
- **Not evaluated**: no experiment has been run yet.

## Module status (after Milestone 9)

| Module (`backend/hqc/…`) | Responsibility | Status | Milestone |
|---|---|---|---|
| `common/schemas/` | Typed data contracts for all stages | **Implemented** | 1 |
| `common/errors.py` | Exception hierarchy (invalid technique, missing dataset, feature-schema mismatch, missing checkpoint, unsupported ATT&CK version, invalid event, quantum backend unavailable, leakage, storage) | **Implemented** | 1 |
| `common/logging.py` | Structured JSON logging with secret redaction | **Implemented** | 1 |
| `common/repro.py` | Seeding, environment capture, git commit lookup | **Implemented** | 1 |
| `config/` | YAML defaults + `.env` + environment overrides; ATT&CK version validation | **Implemented** | 1 |
| `storage/` | `Store` protocol + `SQLiteStore` (stdlib `sqlite3`); evaluation runs are write-once | **Implemented** | 1 |
| `api/` | FastAPI app factory, `GET /health` | **Implemented** (health only; unchanged) | 1 |
| `api/server.py`, `api/v1/` (`routes`, `schemas`, `services`, `state`) | Versioned `/api/v1` over the M7 services: chains, predictions, risk, stored assessments, GET-only recommendations, append-only analyst decisions (two-step approval for HIGH disruption), run summaries | **Implemented** (see `API.md`; no authentication yet) | 8 |
| `common/provenance.py`, `common/download.py` | SHA-256, tracked data manifest; allowlisted, certificate-verified downloads of official sources | **Implemented** | 2 |
| `mitre/` (`stix_parser`, `knowledge_base`, `attack_flow`, `attack_flow_corpus`, `sources`, `build`) | ATT&CK 19.2 STIX normalisation, typed KB API, Attack Flow ordered-sequence parser, corpus summary | **Implemented** (see `ATTACK_KNOWLEDGE_BASE.md`) | 2 |
| `mitre/` detection→technique mapping | **Deliberately not implemented**: CIC-IDS2017 labels are not ATT&CK techniques. Technique evidence comes from explicit sources instead (`attack_chain/evidence`) | n/a | 7 |
| `prediction/vocabulary.py` | Deterministic, versioned technique vocabulary | **Implemented** | 2 |
| `prediction/` (`base`, `dataset`, `baselines`, `markov`) | Output space and normalisation; dataset construction (ID cleanup, unique instances, weighting); B0, B1, M1, M2; model persistence | **Implemented and evaluated** (single step; see `ATTACK_CHAIN_PREDICTION.md`) | 3 |
| `evaluation/` (`splits`, `metrics`, `tuning`, `chain_prediction`, `tracking`) | Leave-one-group-out folds, metrics and bootstrap, nested tuning, experiment orchestration, run folders and SQLite records | **Implemented** (see `EVALUATION.md`) | 3 |
| `prediction/` (`lstm`, `fusion`, `beam_search`) | Small PyTorch LSTM (CPU, deterministic) with checkpoints; Markov+LSTM probability fusion; deterministic beam search | **Implemented and evaluated** (see `LSTM.md`) | 4 |
| `evaluation/` (`multistep`, `sequence_experiment`, `sequence_tracking`) | Multi-step ground truth and metrics; nested LOGO for LSTM, fusion and beam search; run folders with training history and VALIDATION sources | **Implemented** | 4 |
| `detection/` (`dataset`, `preprocessing`, `models`, `evaluation`, `experiment`, `tracking`, `registration`, `schemas`) | CIC-IDS2017 adapter, whole-day split, feature policy, train-only preprocessing, duplicate audit, LogReg/RandomForest, metrics, run tracking, manual-download registration | **Implemented and evaluated** (see `CLASSICAL_DETECTION.md`) | 5 |
| Generic ingestion / preprocessing | Not needed: the CIC-specific adapter and train-only preprocessing live in `detection/`. The unused top-level `ingestion/` and `preprocessing/` placeholder packages were removed | Not implemented | n/a |
| `quantum/` (`feature_maps`, `kernels`, `features`, `models`, `cv`, `band`, `sampling`, `adjudicator`, `noise`, `experiment`, `pipeline`, `tracking`) | Exact batched ZZ/Z feature-map statevectors (validated against Qiskit), fidelity/RBF/linear kernels and diagnostics, train-only angle features, leave-one-training-day-out CV, uncertainty bands from training out-of-fold scores, kernel-SVM adjudicator, Aer noise study, E2–E4 experiments and tracking | **Implemented and evaluated** (see `QUANTUM_ADJUDICATOR.md`; no quantum advantage found or claimed) | 6 |
| `fusion/` (`stacking`) | Platt calibration, logistic stacking, disagreement, `attach_quantum_opinion` (never changes the classical verdict) | **Implemented** | 6 |
| `attack_chain/` (`catalog`, `evidence`, `reconstruction`) | ATT&CK 19.2 validation, typed technique/detection evidence, explicit rule engine, disagreement rule, deterministic correlation, order-preserving reconstruction (`AttackChainService`) | **Implemented** (see `ATTACK_CHAIN_INTEGRATION.md`) | 7 |
| `prediction/service.py` | `PredictionService`: stored M3/M4 models (B1, M1, LSTM fold-00, hybrid α=0.7), top-k next steps, beam paths | **Implemented** (composed configuration not separately evaluated) | 7 |
| `risk/engine.py` | `RiskService`: documented weighted MODEL-DERIVED risk score, fixed thresholds, quantum weight 0 | **Implemented** (see `RISK_ENGINE.md`) | 7 |
| `defense/recommender.py` | `DefenseRecommendationService`: deterministic recommendation-only policy; human approval always required | **Implemented** (see `ADAPTIVE_DEFENSE.md`; guardrail extended) | 7 |
| `pipeline/` (`intelligence`, `scenario`, `config`, `checks`, `tracking`) | `IntelligencePipeline` composing the four services; synthetic scenario loader and validator; integration checks; run tracking | **Implemented** (synthetic end-to-end demo; 13/13 checks) | 7 |
| `frontend/` | React + Vite + TypeScript SOC dashboard over `/api/v1`: overview, assessment submission and detail (observed → predicted chain, risk, classical/quantum evidence, recommendations, append-only analyst decisions), MITRE IDs, evaluation runs. Types generated from the API's OpenAPI document; no backend logic duplicated; executes nothing | **Implemented** (see `FRONTEND.md`) | 9 |

## Data contracts (`hqc.common.schemas`)

| Contract | Notes |
|---|---|
| `SecurityEvent` | Discriminated union on `event_type`: `NetworkFlow`, `AuthenticationEvent`, `SystemEvent`, `APIEvent`. Timestamps must be timezone-aware and are normalised to UTC. Flow features must be finite. Every event carries `data_origin` (REAL / SYNTHETIC). `ground_truth_label` is for evaluation only |
| `DetectionResult` + `QuantumOpinion` | Holds the classical verdict and an optional quantum opinion. `needs_additional_evidence` is true on disagreement, and the classical verdict is never overridden. Since Milestone 5 it also has optional flow ID, timestamp, threshold, uncertainty, feature and preprocessing versions, an offline-only `dataset_label`, and evidence |
| `ATTACKTechnique`, `ATTACKTactic`, `ATTACKMitigation`, `ATTACKDataComponent` | Technique-ID format and parent/sub-technique consistency are validated. Since Milestone 2, techniques carry platforms, detection strategy IDs (`DET####`), data component IDs (`DC####`), revoked/revoked_by, STIX ID and URL. The legacy `data_sources` field was replaced because ATT&CK v18+ deprecates data sources |
| `TechniqueCandidate` | Mapping output: one or more candidates, each with confidence and evidence |
| `AttackStep` | Provenance is `OBSERVED` (requires `event_id`), `DOCUMENTED` (explicitly encoded in curated CTI such as Attack Flow; added in Milestone 2), `INFERRED` or `PREDICTED` |
| `AttackChain` | Order is preserved. Out-of-order timestamps are **rejected, never sorted**. Predicted steps are not allowed in a chain |
| `PredictionResult` | Next-step distribution (sum ≤ 1, no duplicates, sorted) and paths (length and horizon checked). `provenance` is fixed to `PREDICTED` |
| `RiskAssessment` | 0–100 score with required explainable components. Fixed label `MODEL-DERIVED RISK SCORE` |
| `DefenseRecommendation` | The seven action categories; `requires_human_approval` is the literal `true`. Since Milestone 7 it also has optional `chain_id`, `policy_version` and an approval note |
| `RiskAssessment` (Milestone 7 additions) | Optional observed and predicted technique IDs, model versions, policy version, `quantum_disagreement` and `evidence_status` |
| `TechniqueEvidence`, `DetectionEvidence`, `Observation`, `IncidentChain`, `NextTechniquePrediction`, `ResourceContext` (`schemas/intelligence.py`) | Milestone 7 evidence → chain → prediction contracts. Evidence names its source (EXPLICIT_RULE, SYNTHETIC_SCENARIO, ATTACK_FLOW, CLASSICAL_DETECTOR, QUANTUM_SECOND_OPINION). Detection evidence enforces the disagreement rule. Incident chains keep OBSERVED and DOCUMENTED steps apart. Predictions separate next-step probabilities from path scores |
| `EvaluationResult`, `EvaluationFold` | Full run metadata. Since Milestone 4, folds also carry `validation_sources`, which must never overlap the test sources. **Rejects overlapping train/test sources**, both top-level and per fold (cross-validated runs list every fold). Metrics must be present if and only if the status is `EVALUATED`. Since Milestone 3 it also records `git_dirty` |

All contracts forbid unknown fields (`extra="forbid"`) and round-trip through JSON (tested).

## Differences from `docs/analysis/FINAL_ARCHITECTURE.md`
- **Package names:** this build uses `config/` and `common/` instead of `core/`, following the master implementation prompt. The schemas live in `common/schemas/`.
- **Pipeline orchestrator:** `pipeline/` was added in Milestone 7 (`IntelligencePipeline`). It is batch-oriented; replay and streaming are later work.
- **Detection-label → technique mapping tables:** the analysis proposed curated CIC-IDS2017 → ATT&CK mapping tables. Milestone 7 deliberately does **not** provide them, because CIC labels are not ATT&CK techniques. Technique evidence must come from explicit, documented sources.
- **Storage:** the analysis proposed SQLAlchemy. The MVP uses stdlib `sqlite3` behind a `Store` protocol, which avoids a dependency. The protocol allows swapping later.
- **ATT&CK version:** the analysis left the choice between v16.x and latest open. The project uses **19.2**, verified on 2026-10-06 as published (and latest) in MITRE's official index.
- **Attack Flow format:** the analysis parsed STIX JSON copies held in a reference repository. We now download STIX 2.1 exports from the official project site. The tagged release ships only `.afb` files, so the trade-off is recorded in `ATTACK_KNOWLEDGE_BASE.md`.
- **Evaluation package:** `hqc/evaluation/` holds reusable split, metric, tuning and tracking code; the top-level `evaluation/` directory holds only runnable scripts.
- **Unit42 playbooks:** not ingested. They contain no ordering, and the analysis limited them to optional co-occurrence priors.
