"""Safety boundary for the Milestone 8 API (``hqc.api``): no execution paths, no action routes.

Reuses the defense scanner (process / shell / network-client / remote-execution / firewall /
account / cloud modules, os.system-style calls, eval/exec/open, command-like literals). The
API legitimately needs ``sqlite3`` (append-only audit tables) and ``threading`` (locks), so
only those two are allowed in addition. Route contract: GET/POST only; recommendations GET.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from test_defense_no_execution import scan_source

import hqc.api

pytestmark = pytest.mark.guardrail

API_DIR = Path(hqc.api.__file__).parent
ALLOWED_IN_API = frozenset({"sqlite3", "threading"})


def _api_files() -> list[Path]:
    return sorted(API_DIR.rglob("*.py"))


def _violations(path: Path) -> list[str]:
    out = []
    for v in scan_source(path.read_text(encoding="utf-8"), str(path)):
        allowed = any(v.detail == f"forbidden import '{m}'" for m in ALLOWED_IN_API)
        if not allowed:
            out.append(f"{v.file}:{v.line}: {v.detail}")
    return out


@pytest.mark.parametrize("path", _api_files(), ids=lambda p: str(p.relative_to(API_DIR)))
def test_api_module_has_no_execution_paths(path: Path) -> None:
    assert not _violations(path)


def test_api_scan_covers_the_v1_package() -> None:
    names = {str(p.relative_to(API_DIR)) for p in _api_files()}
    assert {"server.py", "v1/routes.py", "v1/state.py", "v1/services.py"} <= names


def test_api_allowlist_does_not_hide_execution(tmp_path: Path) -> None:
    sample = tmp_path / "x.py"
    sample.write_text("import sqlite3\nimport subprocess\nx = 'iptables -F'\n")
    found = _violations(sample)
    assert len(found) == 2 and not any("sqlite3" in f for f in found)


def test_api_routes_offer_no_action_execution() -> None:
    from hqc.api.server import create_api_app
    from hqc.api.v1.state import ApiStateStore
    from hqc.config import Settings
    from hqc.storage import SQLiteStore

    with SQLiteStore(":memory:") as runs:
        app = create_api_app(
            Settings(_env_file=None, environment="test"),  # type: ignore[call-arg]
            state=ApiStateStore(":memory:"),
            evaluation_store=runs,
        )
        paths = app.openapi()["paths"]
    for path, methods in paths.items():
        assert set(methods) <= {"get", "post"}, path
        lowered = path.lower()
        assert not any(w in lowered for w in ("execute", "apply", "isolate", "block", "firewall"))
        if "recommendations" in path and not path.endswith("/decisions"):
            assert set(methods) == {"get"}, path
