# Development guide

## Environment
- Python **3.11** (`requires-python = ">=3.11,<3.12"`).
- Use a project-local virtual environment, `.venv/` (git-ignored).

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev]"
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

## Dependency policy
- `pyproject.toml` declares compatible ranges. `requirements.txt` and `requirements-dev.txt` hold the exact versions verified at each milestone.
- Dependencies are added **only by the milestone that needs them**:

| Milestone | Planned additions |
|---|---|
| 2–3 | none expected (stdlib JSON parsing of ATT&CK / Attack Flow STIX) |
| 4 | `torch` (CPU), `numpy` |
| 5 | `numpy`, `pandas`, `scikit-learn`, `pyarrow` (optional) |
| 6 | `qiskit`, `qiskit-aer`, `qiskit-machine-learning` (pinned together after an install test) |
| 9 | Node toolchain for `frontend/` |

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

## Milestone gate checklist
1. `pytest` all green
2. `ruff check` + `ruff format --check` clean
3. `mypy` (strict) clean
4. Docs updated (`ARCHITECTURE.md` status table, relevant topic docs)
5. Report commands, results and known limitations
