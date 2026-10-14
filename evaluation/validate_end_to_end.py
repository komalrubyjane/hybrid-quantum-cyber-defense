# ruff: noqa: E501  (validation script: long check descriptions are kept on one line)
"""Milestone 10: lightweight end-to-end validation of API -> M7 pipeline -> decisions -> audit.

Uses the real services (local ATT&CK KB + stored M3/M4 artifacts; nothing is trained) behind the
Milestone 8 API with IN-MEMORY API state, so the project's append-only database is untouched.
Submits the SYNTHETIC example request used by the dashboard and walks the analyst workflow.
Writes ``artifacts/final/e2e_validation.json``. Exit code 1 if any check fails; exit code 2
(and the stored record is left untouched) if the services or local artifacts are unavailable.

Usage:
    python evaluation/validate_end_to_end.py
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from hqc.api.server import create_api_app
from hqc.api.v1.state import ApiStateStore
from hqc.config import PROJECT_ROOT, Settings
from hqc.evaluation.prerequisites import EXIT_PREREQUISITE
from hqc.storage import SQLiteStore

REQUEST = PROJECT_ROOT / "frontend" / "src" / "fixtures" / "synthetic-assessment-request.json"
OUT = PROJECT_ROOT / "artifacts" / "final" / "e2e_validation.json"
DISRUPTIVE = {"isolate_affected_host", "block_suspicious_access", "disable_compromised_credentials"}


def _print_checks(checks: list[dict[str, Any]]) -> None:
    for c in checks:
        print(
            ("PASS " if c["passed"] else "FAIL ")
            + c["check"]
            + (f" — {c['detail']}" if c["detail"] else "")
        )


def _abort(checks: list[dict[str, Any]], reason: str, code: int = EXIT_PREREQUISITE) -> int:
    """Stop early; the stored validation record is left untouched."""
    _print_checks(checks)
    print(f"error: {reason}", file=sys.stderr)
    print(f"{Path(OUT).relative_to(PROJECT_ROOT)} was not modified.", file=sys.stderr)
    return code


def main() -> int:
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})

    body = json.loads(REQUEST.read_text(encoding="utf-8"))
    state = ApiStateStore(":memory:")
    settings = Settings(_env_file=None)
    with SQLiteStore(":memory:") as runs:
        client = TestClient(create_api_app(settings, state=state, evaluation_store=runs))
        paths = client.get("/openapi.json").json()["paths"]
        methods = {m for v in paths.values() for m in v}
        check("only GET/POST routes exist", methods <= {"get", "post"}, str(sorted(methods)))
        check(
            "no execution route exists",
            not any(w in p for p in paths for w in ("execute", "apply", "isolate", "block")),
        )
        meta = client.get("/api/v1/meta")
        check(
            "services load from stored artifacts",
            meta.status_code == 200,
            meta.json().get("model_versions", {}).get("HYBRID", ""),
        )
        if meta.status_code != 200:
            return _abort(
                checks,
                f"intelligence services unavailable (HTTP {meta.status_code}): build the local "
                "ATT&CK 19.2 knowledge base and the stored Milestone 3/4 runs first "
                "(see docs/API.md and docs/REPRODUCIBILITY.md).",
            )

        created = client.post("/api/v1/assessments", json=body)
        record = created.json()
        check(
            "assessment submitted (201)",
            created.status_code == 201,
            record.get("assessment_id", ""),
        )
        if created.status_code != 201:
            return _abort(
                checks, f"assessment was not created (HTTP {created.status_code}).", code=1
            )
        aid = record["assessment_id"]
        incidents = record["output"]["incidents"]
        main_chain = incidents[0]
        steps = main_chain["chain"]["chain"]["steps"]
        check(
            "chain has 6 OBSERVED steps",
            [s["provenance"] for s in steps] == ["OBSERVED"] * 6,
            " -> ".join(s["technique_id"] for s in steps),
        )
        pred = main_chain["prediction"]
        check(
            "predictions are PREDICTED (never observed)",
            pred["provenance"] == "PREDICTED" and pred["result"]["provenance"] == "PREDICTED",
            f"top next {pred['result']['next_step'][0]['technique_id']} {pred['result']['next_step'][0]['probability']:.4f}",
        )
        risk = main_chain["risk"]
        check(
            "risk is MODEL-DERIVED and matches the M7 run",
            risk["label"] == "MODEL-DERIVED RISK SCORE"
            and abs(risk["score"] - 76.4492) < 1e-3
            and risk["level"] == "CRITICAL",
            f"{risk['score']} {risk['level']} {risk['evidence_status']}",
        )
        recs = [r for i in incidents for r in i["recommendations"]]
        check(
            "all recommendations PROPOSED and require human approval",
            all(r["status"] == "PROPOSED" and r["requires_human_approval"] is True for r in recs),
            f"{len(recs)} recommendations",
        )
        check(
            "disruptive actions withheld on unresolved disagreement",
            not DISRUPTIVE & {r["action"] for r in main_chain["recommendations"]},
            ", ".join(r["action"] for r in main_chain["recommendations"]),
        )

        # Same scenario without quantum opinions -> CRITICAL plan with HIGH-disruption proposals.
        plain = json.loads(json.dumps(body))
        for o in plain["observations"]:
            if o.get("detection") and o["detection"].get("quantum"):
                o["detection"].update(
                    {
                        "quantum": None,
                        "quantum_disagreement": False,
                        "evidence_status": "NO SECOND OPINION",
                    }
                )
        aid2 = client.post("/api/v1/assessments", json=plain).json()["assessment_id"]
        views = client.get(f"/api/v1/assessments/{aid2}/recommendations").json()
        isolate = next(v for v in views if v["recommendation"]["action"] == "isolate_affected_host")
        rid = isolate["recommendation"]["recommendation_id"]
        base = f"/api/v1/assessments/{aid2}/recommendations/{rid}/decisions"
        early = client.post(base, json={"decision": "APPROVED", "analyst": "validator"})
        check(
            "HIGH-disruption approval without acknowledgement -> 409",
            early.status_code == 409,
            early.json().get("detail", ""),
        )
        ack = client.post(base, json={"decision": "ACKNOWLEDGED", "analyst": "validator"})
        appr = client.post(base, json={"decision": "APPROVED", "analyst": "validator"})
        check(
            "acknowledge then approve recorded (201, executed: false)",
            ack.status_code == appr.status_code == 201
            and ack.json()["executed"] is False
            and appr.json()["executed"] is False,
        )
        other = next(v for v in views if v["recommendation"]["action"] == "increase_monitoring")
        rej = client.post(
            f"/api/v1/assessments/{aid2}/recommendations/{other['recommendation']['recommendation_id']}/decisions",
            json={"decision": "REJECTED", "analyst": "validator", "note": "validation"},
        )
        check(
            "rejection recorded (executed: false)",
            rej.status_code == 201 and rej.json()["executed"] is False,
        )
        after = client.get(f"/api/v1/assessments/{aid2}/recommendations").json()
        check(
            "stored recommendations stay PROPOSED after decisions",
            all(
                v["recommendation"]["status"] == "PROPOSED" and v["executed"] is False
                for v in after
            ),
        )
        history = client.get(base).json()
        check(
            "decision history is the audit trail",
            [d["decision"] for d in history] == ["ACKNOWLEDGED", "APPROVED"],
        )
        try:
            state._conn.execute("DELETE FROM api_decisions")
            deleted = True
        except sqlite3.DatabaseError:
            deleted = False
        check("audit log is append-only (DELETE rejected)", not deleted)
        bad = client.post("/api/v1/assessments", json={"observations": []})
        check(
            "invalid request -> 422 without internal paths",
            bad.status_code == 422 and "/Users" not in bad.text,
        )
        missing = client.get("/api/v1/assessments/asm-none")
        check("unknown assessment -> 404", missing.status_code == 404)
        _ = aid
    passed = all(c["passed"] for c in checks)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "scope": "API + M7 pipeline + analyst decisions (in-memory API state; SYNTHETIC scenario)",
                "passed": passed,
                "checks": checks,
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    _print_checks(checks)
    print(f"wrote {Path(OUT).relative_to(PROJECT_ROOT)}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
