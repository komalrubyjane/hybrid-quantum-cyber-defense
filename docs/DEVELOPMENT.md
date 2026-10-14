# Development guide

## Environment
- Python **3.11** (`requires-python = ">=3.11,<3.12"`).
- Use a project-local virtual environment, `.venv/` (git-ignored).

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev,quantum]"
```

The package is installed in editable mode from `backend/`. `hqc.config.PROJECT_ROOT` resolves relative paths against the repository root, so run commands from the repository root.

## Everyday commands
| Task | Command |
|---|---|
| Tests | `.venv/bin/python -m pytest` |
| Tests by group | `pytest tests/unit`, `pytest -m integration`, `pytest -m guardrail` |
| Lint | `.venv/bin/ruff check backend tests` |
| Format | `.venv/bin/ruff format backend tests` |
| Types (strict) | `.venv/bin/mypy` |
| API | `.venv/bin/uvicorn hqc.api.app:create_app --factory --host 127.0.0.1 --port 8000` |
| Register CIC-IDS2017 (after manual download) | `.venv/bin/python scripts/register_cicids2017.py` |
| Classical detection (CIC-IDS2017) | `.venv/bin/python evaluation/run_classical_detection.py` |
| Synthetic end-to-end integration demo (Milestone 7; needs the local KB and stored M3–M6 artifacts) | `.venv/bin/python evaluation/run_integration_demo.py` (~2 s) |
| Defense and API safety scan | `.venv/bin/pytest -m guardrail` |
| Final tables, figures and reproducibility audit (M10; stored runs only) | `.venv/bin/python evaluation/build_final_report.py` |
| End-to-end validation (M10; in-memory API state) | `.venv/bin/python evaluation/validate_end_to_end.py` |
| Dashboard (Milestone 9) | `cd frontend && npm ci && npm run dev` (checks: `npm run check`) |
| Re-export the API contract for the dashboard | `.venv/bin/python scripts/export_frontend_contract.py [--responses] && (cd frontend && npm run gen:api)` |
| Run the versioned API (localhost) | `.venv/bin/uvicorn hqc.api.server:create_api_app --factory --host 127.0.0.1 --port 8000` |
| Quantum second opinion (needs the Milestone 5 run and models) | `.venv/bin/python evaluation/run_quantum_adjudicator.py` (~16 min, CPU) |
| LSTM / fusion / beam search (real data, ~9 min on Apple M4 CPU) | `.venv/bin/python -W ignore evaluation/run_sequence_models.py` |
| Prediction baselines (real data, ~2 min) | `.venv/bin/python evaluation/run_markov_baseline.py [--weighting document\|raw\|unique]` |
| Lint incl. scripts | `.venv/bin/ruff check backend tests scripts evaluation` |

## Dependency policy
- `pyproject.toml` declares compatible ranges. `requirements.txt` and `requirements-dev.txt` hold the exact versions verified at each milestone.
- Dependencies are added **only by the milestone that needs them**:

| Milestone | Dependencies added |
|---|---|
| 2 | `certifi` (added: CA bundle for certificate-verified downloads, because the python.org macOS build ships without one). STIX parsing uses stdlib `json` |
| 3 | none added (pure Python; NumPy not needed) |
| 4 | `torch` (added: 2.14.1, macOS arm64 CPU wheel, no CUDA). `numpy` not needed; torch's import-time "NumPy missing" warning is harmless and suppressed in `hqc.prediction.lstm` |
| 5 | `numpy`, `pandas`, `scikit-learn` (added); dev: `pandas-stubs`. mypy ignores missing stubs only for `sklearn.*` and `joblib` |
| 6 | `qiskit==2.5.2`, `qiskit-aer==0.17.2` (optional `quantum` extra, pinned after an install test) and `scipy` (declared because it is imported directly). `qiskit-machine-learning` was **not** needed |
| 7, 8 | none added |
| 9 | Node toolchain for `frontend/` (React, Vite, TypeScript 5.9, Vitest, ESLint, openapi-typescript; exact versions in `frontend/package-lock.json`) |
| 10 | none added (figures are dependency-free SVG) |

## Configuration
Precedence, highest first:
1. Explicit `Settings(...)` arguments
2. Environment variables
3. `.env`
4. `configs/default.yaml` (or `$HQC_CONFIG_FILE`)

Most variables use the `HQC_` prefix. The ATT&CK version also accepts the plain name `ATTACK_VERSION`. Unknown keys and wildcard CORS origins are rejected.

## Logging
Use `hqc.common.logging.get_logger(__name__)` and pass context through `extra={"stage": ...}`. Output is JSON lines by default. Keys and inline `key=value` fragments that look like secrets (password, token, api_key, secret, credential, authorization, …) are redacted. **Never log credentials**, even though redaction exists as a safety net.

## Testing rules
- Tests must run **without downloaded datasets**. Use `tests/fixtures/` (synthetic, clearly labelled).
- `tests/conftest.py` clears `HQC_*` and `ATTACK_VERSION` environment variables for every test.
- The defense guardrail test (`tests/guardrails/test_defense_no_execution.py`) must stay green. It fails on any process, shell, network, remote-execution, firewall or system-control import or call inside `hqc.defense`.

## Experiments
- Experiment configuration lives in `configs/` (e.g. `chain_prediction.yaml`). Grids are fixed *before* a real run.
- Every run writes `reports/runs/<run-id>/` (git-ignored) and an `EvaluationResult` in SQLite.
- The record includes the git commit **and** `working_tree_dirty`.
- Never edit run outputs by hand. Copy numbers into docs only from `summary.md` or `metrics.json`.

## Milestone gate checklist
1. `pytest` all green
2. `ruff check` + `ruff format --check` clean
3. `mypy` (strict) clean
4. Docs updated (`ARCHITECTURE.md` status table, relevant topic docs)
5. Report commands, results and known limitations
