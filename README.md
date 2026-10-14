# Hybrid Quantum-AI Intelligence Framework for Cyberattack Chain Prediction and Adaptive Defense

A research prototype for defensive cybersecurity. It combines classical ML detection, a quantum-kernel *second opinion* (local simulator only), MITRE ATT&CK knowledge, attack-chain reconstruction and prediction, explainable model-derived risk scoring, and **recommendation-only** defense guidance.

> **Status: Milestone 10 complete — final research result.** All ten milestones are implemented:
> - Milestone 1: foundation.
> - Milestone 2: ATT&CK 19.2 knowledge base and Attack Flow corpus.
> - Milestone 3: Markov baselines.
> - Milestone 4: LSTM, fusion and beam search.
> - Milestone 5: classical intrusion detection on CIC-IDS2017.
> - Milestone 6: quantum-kernel second opinion.
> - Milestone 7: attack-chain integration, risk and recommendation-only defense.
> - Milestone 8: versioned FastAPI.
> - Milestone 9: React dashboard.
> - Milestone 10: final evaluation, reproducibility audit and documentation.
>
> **Final findings (measured; details in `docs/FINAL_EVALUATION.md`):**
> - **Detection:** the pre-registered Random Forest is very precise (0.9955, benign FPR 0.04%) on unseen CIC-IDS2017 days, but recalls only 28% of unseen attack traffic.
> - **Attack prediction:** the frequency baseline B1 is strongest on top-1 and log loss. The LSTM is better only on top-5 (+0.030). Multi-step chain prediction is not established.
> - **Quantum:** **no quantum advantage was observed**. The entangling ZZ kernel was never significantly better than an RBF-SVM and was the weakest fused second opinion.
> - **Integration:** demonstrated **only on a SYNTHETIC scenario**. Risk is MODEL-DERIVED.
> - **Safety:** every recommendation requires human approval, and **nothing is ever executed automatically**. The system is decision support, not autonomous cyber defense.
>
> Final tables and figures are in `artifacts/final/` (generated from stored runs by `evaluation/build_final_report.py`).

## Research and safety principles
- **No unsupported claims.** We make no claim of quantum advantage, real-world prediction accuracy or production readiness unless an experiment demonstrates it. A null quantum result is a valid result.
- **Defense is advisory only.** Every recommendation has `requires_human_approval = true`, and the `hqc.defense` package is statically checked so it can never execute actions (`tests/guardrails/`).
- **Leakage-aware evaluation.** Attack sequences are split by source document, and an evaluation record with overlapping train and test sources is rejected by the schema.
- **ATT&CK technique IDs** (e.g. `T1059.004`) are the internal vocabulary. Names are for display only.
- **Synthetic data is always labelled** `data_origin = SYNTHETIC`.

## Pipeline (target)
```
Security events → ingestion → normalisation/validation → classical detection → quantum second opinion (gated)
→ ATT&CK mapping → attack-chain reconstruction → attack-chain prediction → risk → defense recommendations → SOC dashboard
```
See `docs/ARCHITECTURE.md` for each module's implementation status. The design rationale and the reference-repository analysis are in `docs/analysis/`.

## Quick start (Python 3.11, Node.js ≥ 22.22 — tested with 24)
```bash
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev,quantum]"          # or exact pins: pip install -r requirements-dev.txt && pip install -e .
.venv/bin/python -m pytest                          # runs without any downloaded dataset (real-data tests skip)
.venv/bin/uvicorn hqc.api.server:create_api_app --factory --host 127.0.0.1 --port 8000
curl http://127.0.0.1:8000/health                   # in another terminal

cd frontend && npm ci && npm run dev                # dashboard: http://localhost:5173
```
Configuration lives in `configs/default.yaml`. Environment variables override it; see `.env.example`.

**What works on a fresh clone.** Datasets, trained models, stored runs and databases are local and not in Git. Without them:
- `/health`, `/api/v1/runs` and `/api/v1/assessments` work (the run and assessment lists start empty).
- The intelligence endpoints (`/api/v1/meta`, assessments submission, predictions) return **503** until the knowledge data below is built and the Milestone 3/4 runs exist.
- Each evaluation run gets a new timestamped ID. After regenerating runs, update the run IDs pinned in `configs/integration.yaml` (and the other files listed in `docs/REPRODUCIBILITY.md`).
- The final results are committed in `artifacts/final/`.

### Knowledge data (official sources, ~55 MB total)
```bash
.venv/bin/python scripts/fetch_attack.py              # ATT&CK Enterprise 19.2 STIX (version verified)
.venv/bin/python scripts/build_attack_kb.py
.venv/bin/python scripts/fetch_attack_flow.py         # MITRE CTID Attack Flow corpus (STIX)
.venv/bin/python scripts/build_attack_flow_corpus.py
.venv/bin/python scripts/build_vocabulary.py
```
Tests run without these files; real-data tests skip when the files are absent. See `docs/ATTACK_KNOWLEDGE_BASE.md`.

### Prediction baselines (Milestone 3)
```bash
.venv/bin/python evaluation/run_markov_baseline.py     # ~2 min; writes reports/runs/<run-id>/
```
See `docs/EVALUATION.md` for the protocol (nested leave-one-group-out, macro/micro, bootstrap CIs).

### Dashboard (Milestone 9)
```bash
cd frontend && npm ci && npm run dev        # http://localhost:5173 (API on 127.0.0.1:8000; its CORS default)
npm run check                               # typecheck + lint + tests with coverage + production build
```

### Versioned API (Milestone 8)
```bash
.venv/bin/uvicorn hqc.api.server:create_api_app --factory --host 127.0.0.1 --port 8000
# http://127.0.0.1:8000/docs  (recommendation-only; decisions are recorded, never executed)
```

### Synthetic integration demo (Milestone 7)
Needs the local ATT&CK KB and the stored Milestone 3–6 artifacts. Nothing is retrained or executed:
```bash
.venv/bin/python evaluation/run_integration_demo.py   # ~2 s
.venv/bin/pytest -m guardrail                           # defense safety scan
```

### Quantum second opinion (Milestone 6)
Requires the Milestone 5 run and its models. It reads them and never modifies them:
```bash
.venv/bin/python evaluation/run_quantum_adjudicator.py    # ~16 min on an Apple M4 CPU
```

### Classical detection (Milestone 5)
Download `GeneratedLabelledFlows.zip` manually from the official UNB page (registration form; see `docs/CIC_IDS2017.md`) into `data/raw/cicids2017/`, then:
```bash
.venv/bin/python scripts/register_cicids2017.py
.venv/bin/python evaluation/run_classical_detection.py      # ~3 min on an Apple M4 CPU
```

### LSTM, fusion and beam search (Milestone 4)
```bash
.venv/bin/python -W ignore evaluation/run_sequence_models.py   # ~9 min on an Apple M4 CPU
```

## Repository layout
| Path | Purpose |
|---|---|
| `backend/hqc/` | Python package (`common/` schemas, errors, logging, repro; `config/`; `storage/`; `api/`; stage packages) |
| `configs/` | YAML configuration |
| `tests/` | `unit/`, `integration/`, `guardrails/`, `fixtures/synthetic/` |
| `data/` | Local datasets (git-ignored; only `README.md` and `MANIFEST.yaml` are tracked) |
| `models/` | Committed technique vocabulary. Trained models (`models/generated/`) are git-ignored and regenerated by the evaluation scripts (see `models/README.md`) |
| `reports/` | Experiment outputs (`reports/runs/` is git-ignored) |
| `artifacts/final/` | Committed final record: results, tables (Markdown + CSV), SVG figures, reproducibility and end-to-end validation (built by `evaluation/build_final_report.py`) |
| `scripts/` | Data download and build scripts |
| `evaluation/` | Runnable experiment scripts (reusable code lives in `backend/hqc/evaluation/`) |
| `frontend/` | React + Vite + TypeScript dashboard (Milestone 9) |
| `docs/` | Project documentation; `docs/analysis/` holds the pre-implementation analysis |

## Reference repositories and licensing
Five reference repositories were analysed (`docs/analysis/`). **None is a dependency and no code is copied from them.**
- R1 (MITRE attack-chain), R4 (PI-VQC) and R5 (Cyberattack-Prediction) have no license, so they are **reference only**.
- R2 (CRIDAP) and R3 (Hybrid ML-QML) are MIT-licensed. If code from them is ever adapted, it will carry their copyright notice and be listed in `docs/THIRD_PARTY_NOTICES.md`.
- The repository contains **no third-party code**.

Datasets (CIC-IDS2017, UNSW-NB15) and knowledge sources (ATT&CK, Attack Flow) have their own terms. See `docs/DATASETS.md` and `docs/THIRD_PARTY_NOTICES.md` (MITRE ATT&CK © notice, Attack Flow Apache-2.0).

## License
**Proprietary — all rights reserved.** © the authors. This project is **not open source**, and no licence is granted to use, copy, modify or distribute it. Publishing the source for review does not grant such a licence. Contact the authors for permission.

Third-party data and dependencies keep their own licences; see `docs/THIRD_PARTY_NOTICES.md`.
