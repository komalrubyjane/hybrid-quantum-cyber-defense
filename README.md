# Hybrid Quantum-AI Intelligence Framework for Cyberattack Chain Prediction and Adaptive Defense

A research prototype for defensive cybersecurity. It combines classical ML detection, a quantum-kernel *second opinion* (local simulator only), MITRE ATT&CK knowledge, attack-chain reconstruction and prediction, explainable model-derived risk scoring, and **recommendation-only** defense guidance.

> **Status: Milestone 1 (foundation) complete.** No models are trained, no datasets are downloaded, and no detection, prediction or quantum results exist yet. Any metric that appears in this repository later will come from a stored experiment run under `reports/runs/`.

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

## Quick start (Python 3.11)
```bash
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev]"          # or: pip install -r requirements-dev.txt && pip install -e .
.venv/bin/python -m pytest                  # runs without any downloaded dataset
.venv/bin/uvicorn hqc.api.app:create_app --factory --host 127.0.0.1 --port 8000
curl http://127.0.0.1:8000/health
```
Configuration lives in `configs/default.yaml`. Environment variables override it; see `.env.example`.

## Repository layout
| Path | Purpose |
|---|---|
| `backend/hqc/` | Python package (`common/` schemas, errors, logging, repro; `config/`; `storage/`; `api/`; stage packages) |
| `configs/` | YAML configuration |
| `tests/` | `unit/`, `integration/`, `guardrails/`, `fixtures/synthetic/` |
| `data/` | Local datasets (git-ignored; only `README.md` and `MANIFEST.yaml` are tracked) |
| `models/` | Model metadata. Generated checkpoints are git-ignored |
| `reports/` | Experiment outputs (`reports/runs/` is git-ignored) |
| `training/`, `evaluation/`, `scripts/`, `notebooks/` | Filled in by later milestones |
| `frontend/` | React + Vite + TypeScript dashboard (Milestone 9) |
| `docs/` | Project documentation; `docs/analysis/` holds the pre-implementation analysis |

## Reference repositories and licensing
Five reference repositories were analysed (`docs/analysis/`). **None is a dependency and no code is copied from them.**
- R1 (MITRE attack-chain), R4 (PI-VQC) and R5 (Cyberattack-Prediction) have no license, so they are **reference only**.
- R2 (CRIDAP) and R3 (Hybrid ML-QML) are MIT-licensed. If code from them is ever adapted, it will carry their copyright notice and be listed in `docs/THIRD_PARTY_NOTICES.md`.
- Milestone 1 contains **no third-party code**.

Datasets (CIC-IDS2017, UNSW-NB15) and knowledge sources (ATT&CK, Attack Flow) have their own terms. See `docs/DATASETS.md`.

## License
Not yet chosen; all rights reserved by the authors until a license is added.
