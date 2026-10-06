# Integration Plan

**Status:** PROPOSED. Awaiting user approval before any application code is written.
**Related:** `REPOSITORY_ANALYSIS.md` (evidence), `LICENSE_AND_REUSE_AUDIT.md` (what is allowed), `FINAL_ARCHITECTURE.md` (target design).

---

## 1. What each repository contributes

| Repo | Contribution to our system | Form |
|---|---|---|
| R1 MITRE Attack-Chain | Problem framing: hybrid Markov + LSTM forecasting, beam expansion, likelihood × impact risk. Attack Flow DFS extraction idea. Pointers to the upstream sequence corpora | **Ideas + upstream data sources** (no code) |
| R2 CRIDAP | Module decomposition, normalized-event pattern, FastAPI endpoint layout, entity-risk weighted formula, privacy rules, recommendation-only rule-table advisor, tests and Docker skeleton | **Adapt (MIT)** |
| R3 Hybrid ML-QML | CIC-IDS2017 loading and cleaning steps, classical baselines, RF-importance → PCA → QSVC workflow, Qiskit 2.4 / qiskit-ml 0.9 wiring | **Adapt (MIT)** |
| R4 PI-VQC | Ising-style ansatz concept, Aer depolarizing + readout noise-model design, noise-sweep methodology. Also a cautionary example of the parameter-shift pitfall | **Ideas only** |
| R5 Cyberattack-Prediction | Concepts for uncertainty (MC-Dropout), drift detection (KS), calibration (temperature scaling), explainability (IG, counterfactuals), continual learning (EWC + replay) | **Ideas only** (post-MVP) |

## 2. Reuse / rewrite / reference-only decisions

### 2.1 Reuse (adapt with attribution; MIT)
| Item | Source | Adaptation needed |
|---|---|---|
| Event normalisation pattern (field aliasing, defaults) | R2 `src/ingestion/log_parser.py` | Generalise to an `Event` Pydantic model; add flow-dataset adapters |
| Privacy rules PRIV-001..005 | R2 `src/privacy/privacy_monitor.py` | Move thresholds to config. Optional context signals for `S_ctx` |
| Entity-risk weighted-sum structure and level thresholds | R2 `src/scoring/risk_scorer.py` | Becomes one component (`S_ctx`) of the new risk model. Weights in YAML |
| Rule-table advisor pattern | R2 `src/advisor/defense_advisor.py` | Replaced by a catalog-driven recommender. Fix the unreachable privilege rule |
| API endpoint naming (`/summary`, `/risk-scores`, `/attack-chains`, `/recommendations`, `/entity/{id}`) | R2 `src/dashboard/api.py` | Rewrite with schemas and a live DB. **Remove the `StaticFiles(".")` mount and wildcard CORS** |
| Synthetic sample events | R2 `data/sample_logs/sample_events.json` | Test fixture only |
| CIC-IDS2017 cleaning steps (strip column names, inf→NaN, drop) | R3 notebook | Add dedupe, identifier policy and train-only fitting |
| Classical baselines + QSVC wiring | R3 notebook | Rewrite as modules with function-style feature maps, matched budgets and full metrics |

Every adapted file gets a header naming the source repo, commit and MIT notice, plus an entry in `docs/THIRD_PARTY_NOTICES.md`.

### 2.2 Rewrite (our own implementation, informed by the references)
- ATT&CK STIX 2.1 knowledge base and validated label → TID mapping tables (replaces R1's name-based `.xls` handling).
- Sequence corpora builders for Attack Flow (DFS), Unit42 (co-occurrence) and ATT&CK campaigns/groups (co-occurrence).
- Smoothed variable-order Markov, LSTM/GRU, hybrid interpolation, beam search and Monte-Carlo rollouts.
- Chain reconstruction, ordered by timestamp.
- Quantum kernel adjudicator, kernel diagnostics, noise study, and (stretch) a VQC with correct gradients.
- Fusion and uncertainty.
- Unified risk model.
- Catalog + ATT&CK-mitigation defense recommender with guardrails.
- SQLite storage and audit log; orchestrator; API; React dashboard.
- Evaluation harness (E1–E5, chain prediction, risk, defense, end-to-end) and the reproducibility tooling.

### 2.3 Reference-only (no code reuse)
| Repo | Why | What we take |
|---|---|---|
| R1 | No license; explicit "contact author before using" | Algorithmic ideas (standard methods), corpus pointers. **Use the upstream data, not R1's copies.** Do not use the severity CSV |
| R4 | No license; core training code is incorrect | Concepts only |
| R5 | No license; synthetic-only, untrained temporal module | Concepts only, implemented from the original papers |

## 3. License and reuse concerns (summary)
1. R1, R4 and R5 have **no license**, so their code is treated as all rights reserved: **REFERENCE ONLY — LICENSE/REUSE STATUS REQUIRES VERIFICATION**.
2. Third-party data inside R1 carries its own terms: ATT&CK (MITRE ToU), Attack Flow (Apache-2.0, to verify), Unit42 (MIT). Fetch it from upstream and keep the notices.
3. CIC-IDS2017 and UNSW-NB15 are research-use datasets with citation requirements (terms to verify at the official sources). We never commit them; we always download them with a script and a checksum.
4. R2 and R3 (MIT) require their copyright notices in adapted code.
5. EPSS and KEV are CVE-level. Using them for technique-level risk would need a separately sourced, documented CVE→technique mapping, so they are deferred.

---

## 4. Step-by-step implementation plan

Each phase ends with explicit exit criteria. **Nothing starts until you approve.** Time estimates assume one developer working part-time and are rough.

### Phase 0 — Foundation (≈ 2–3 days)
- Decide project placement (Option A or B in `FINAL_ARCHITECTURE.md` §12) and the ATT&CK version.
- Scaffold `pyproject.toml` (Python 3.11, extras `[quantum]`, `[dl]`, `[api]`, `[dev]`), ruff, mypy, pytest, pre-commit, Makefile.
- `hqc.core`: config loader, **Pydantic data contracts**, seed utility, run-metadata writer.
- `scripts/download_*.py` and `data/MANIFEST.yaml`, starting with the small knowledge sources: ATT&CK STIX, Attack Flow, Unit42.
- **Install test:** pin qiskit / qiskit-aer / qiskit-machine-learning versions that work together on Python 3.11.
- **Exit:** `make test` passes on contract tests; KB sources download with verified checksums.

### Phase 1 — ATT&CK knowledge base + chain-prediction core (≈ 1–1.5 weeks). *Implement first.*
- `mitre/kb.py`: techniques, tactics, parents, mitigations, `mitigates`, campaign/group `uses`.
- Mapping tables for CIC-IDS2017 and UNSW-NB15, plus a test that every TID exists and is not revoked.
- `prediction/corpus.py`: Attack Flow DFS sequences and Unit42/campaign co-occurrence sets, with provenance.
- `prediction/`: B0, B1, smoothed Markov (M1), beam search and rollouts.
- `evaluation/`: grouped CV harness, top-k / MRR / NLL / hit@k metrics.
- **Exit:** a reproducible baseline table (B0, B1, M1) under leave-one-flow-out CV, generated by a script.

### Phase 2 — LSTM + hybrid predictor (≈ 1 week)
- M2 LSTM/GRU with the tactic auxiliary head and early stopping on grouped validation; M3 interpolation tuning.
- Data-source ablations (Attack Flow only vs pseudo-ordered additions).
- **Exit:** the chain-prediction table for B0–M3, with CIs; model cards written.

### Phase 3 — Detection pipeline on CIC-IDS2017 (≈ 1–1.5 weeks)
- CIC-IDS2017 download script (official source) + manifest; adapter; cleaning; train-only pipeline.
- LR / RF / HistGB with calibration; random and **day-based** splits; full metrics; latency.
- Ambiguity-band selection from out-of-fold predictions.
- **Exit:** E1 report; band coverage documented.

### Phase 4 — Quantum Kernel Adjudicator (≈ 1.5–2 weeks)
- Feature maps (ZZ entangling, Z product control), statevector kernel, SVC, calibration, bandwidth CV.
- Kernel diagnostics (alignment, concentration, geometric difference).
- E2 matched-budget experiments, E3 hybrid adjudication with an **RBF-SVM adjudicator control**, E4 noise sweep (small N).
- Fusion (stacking) and the disagreement-based uncertainty signal.
- **Exit:** E2–E4 reports. The adjudicator is integrated behind a config flag, and inference latency is measured.

### Phase 5 — Mapping → chains → risk → defense (≈ 1–1.5 weeks)
- Alert creation with technique evidence; chain reconstruction; anchoring to the predictor.
- Risk model with component outputs, property tests (hypothesis) and sensitivity analysis.
- Defense catalog + ATT&CK-mitigation recommender, plus the **guardrail test suite**.
- Synthetic scenario generator with pre-registered severity labels.
- **Exit:** end-to-end batch run on a CIC-IDS2017 subset and synthetic scenarios; risk and defense evaluations reported.

### Phase 6 — Storage, API, dashboard (≈ 1.5–2 weeks)
- SQLite schema, repositories, audit log; replay orchestrator.
- FastAPI routers: health, summary, alerts, entities, chains, forecasts, risk, recommendations (GET), analyst decisions (POST, recorded only).
- React dashboard:
  - Overview and alert queue (classical vs quantum scores, disagreement)
  - Entity timeline on ATT&CK tactics
  - Forecast tree with probabilities and reach probabilities
  - ATT&CK matrix heatmap (observed vs predicted)
  - Recommendation queue with approve/reject (record-only)
  - Experiments page
- Docker compose (api + frontend).
- **Exit:** `docker compose up` shows the replayed demo; API integration tests pass.

### Phase 7 — Secondary validation and hardening (≈ 1 week)
- UNSW-NB15 adapter and evaluation; end-to-end metrics; README; reproducibility check from a clean clone.

### Stretch (post-MVP)
- VQC with correct gradients and a trainability study (E5).
- MC-Dropout / temperature scaling / drift detection / explainability (R5 concepts).
- D3FEND mapping; EPSS/KEV via a documented CVE→technique bridge.
- Transformer or GNN sequence models.
- IBM Runtime backend.

---

## 5. Major technical risks

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| 1 | **No quantum advantage** (likely at 4–8 qubits on tabular flows) | Weak "quantum" headline | Frame it as a controlled research question. Report kernel diagnostics (geometric difference) that explain the outcome. The adjudicator still serves a measurable role (the disagreement → evidence signal) |
| 2 | **Kernel exponential concentration**: ZZ kernels can approach the identity as d and reps grow | Quantum kernel degenerates | Bandwidth scaling, d ≤ 8, concentration diagnostics |
| 3 | **Simulation cost** (O(N²) kernel, noisy shots) | Slow experiments | Statevector kernel with caching; N ≤ 2k; noise study on N ≤ 300; inference against support vectors only |
| 4 | **Vocabulary gap**: network flows reveal ~6–10 techniques while the predictor knows hundreds | Short, shallow observed chains from real data | Anchoring with confidence; synthetic scenarios for long chains; report real and synthetic results separately |
| 5 | **Scarce ordered sequence data**: 39 Attack Flow documents | LSTM overfits; high-variance estimates | Small models, strong smoothing, the Markov backoff, grouped CV with CIs. Pseudo-ordered data is used only as an ablation |
| 6 | **Dataset label quality / shortcuts** (CIC-IDS2017 duplicates, label errors, `Destination Port`) | Inflated detection scores | Dedupe, shortcut ablation, day-based holdout, consider a corrected relabelling |
| 7 | **Evaluation leakage**, which recurred in four of the five references | Invalid conclusions | Train-only pipelines, grouped splits, leakage unit tests (e.g. assert no group overlap) |
| 8 | **Qiskit API churn** (class → function feature maps; qiskit-ml compatibility) | Breakage | Pin versions after the Phase 0 install test; a thin wrapper in `hqc.quantum` |
| 9 | **Risk score has no ground truth** | Unverifiable claims | Pre-registered synthetic labels, property tests, sensitivity analysis. Present weights as policy, not truth |
| 10 | **Unsafe defense semantics** | Policy violation | Recommendation-only design, guardrail tests, human approval, audit log |
| 11 | **Licensing**: R1 code unavailable for reuse | Can't directly replicate R1 numbers | Independent re-implementation, compared on our own leakage-free protocol. Optionally contact the authors |
| 12 | **Scope creep** (dashboard polish, Gen-AI reports) | Delays | MVP definition below; stretch items gated |

---

## 6. Expected MVP

A locally runnable system (`make setup && make data-small && make train-mvp && make serve`) that:
1. Ingests a CIC-IDS2017 subset, plus synthetic multi-stage scenarios, in replay mode.
2. Detects attacks with a calibrated RF/HistGB model. Ambiguous events go to a **statevector-simulated ZZ quantum-kernel adjudicator**, and the scores are fused.
3. Maps detections to validated ATT&CK technique IDs and reconstructs per-entity chains.
4. Forecasts next techniques (top-k) and multi-step paths with the hybrid Markov + LSTM model, including reach probabilities for high-impact tactics.
5. Computes a component-explained 0–100 entity risk.
6. Produces ranked, **recommendation-only** defense actions (the seven required types plus ATT&CK mitigations), each requiring analyst approval.
7. Serves all of this through FastAPI to a minimal React SOC dashboard: alerts, entity chain view, forecast, risk, recommendations.
8. Ships with evaluation reports E1–E3 and chain-prediction results generated from stored runs, with no hand-entered numbers.

Out of scope for the MVP: real hardware, VQC, autonomous response, live packet capture, LLM-generated reports.

## 7. What to implement first

**Phase 0, then Phase 1: the data contracts and the ATT&CK knowledge base, followed by the chain-prediction baselines and their leakage-free evaluation harness.**

**Why this order:**
- It is the system's central novelty: prediction over ATT&CK feeding risk and defense.
- All required data is small and public: ATT&CK STIX, 39 Attack Flow docs, 85 Unit42 bundles. No large downloads or GPU are needed.
- It fixes the most consequential defect in the strongest reference, R1's evaluation leakage.
- It fixes the canonical TID vocabulary that every later stage (mapping, risk, defense, dashboard) depends on.

Detection (Phase 3) and quantum (Phase 4) follow. They need the large CIC-IDS2017 download, which we will do only after you approve.

## 8. Decisions needed from you before implementation
1. **Project placement:** Option A (workspace root, references git-ignored) or **Option B (new folder, recommended)**.
2. **ATT&CK version:** v16.x (matches R1, eases comparison) or the latest stable release.
3. **Frontend:** React + Vite + TypeScript (recommended) or a simpler server-rendered or Streamlit MVP first.
4. **Data downloads:** approval to download CIC-IDS2017 (≈ 1 GB+ CSVs) and UNSW-NB15 from the official sources in Phase 3 and Phase 7.
5. **Contacting authors:** whether to ask the R1, R4 and R5 authors for licensing clarification. This is not required by the plan.
