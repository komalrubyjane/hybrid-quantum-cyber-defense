"""API state: stored assessments and the APPEND-ONLY analyst-decision audit log.

Stdlib ``sqlite3`` in API-owned tables (``api_assessments``, ``api_decisions``) next to the
Milestone 1 store. SQLite triggers reject every UPDATE and DELETE on both tables, so stored
assessments are immutable and decisions can only be appended. Nothing here executes actions.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from hqc.api.v1.schemas import AssessmentRecord, Decision, DecisionRecord
from hqc.common.schemas.base import utc_now

_SCHEMA = """
CREATE TABLE IF NOT EXISTS api_assessments (
    assessment_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL REFERENCES api_assessments(assessment_id),
    recommendation_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    analyst TEXT NOT NULL,
    note TEXT,
    recorded_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS api_assessments_no_update BEFORE UPDATE ON api_assessments
BEGIN SELECT RAISE(ABORT, 'api_assessments is immutable'); END;
CREATE TRIGGER IF NOT EXISTS api_assessments_no_delete BEFORE DELETE ON api_assessments
BEGIN SELECT RAISE(ABORT, 'api_assessments is immutable'); END;
CREATE TRIGGER IF NOT EXISTS api_decisions_no_update BEFORE UPDATE ON api_decisions
BEGIN SELECT RAISE(ABORT, 'api_decisions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS api_decisions_no_delete BEFORE DELETE ON api_decisions
BEGIN SELECT RAISE(ABORT, 'api_decisions is append-only'); END;
"""


class ApiStateStore:
    def __init__(self, db_path: Path | str) -> None:
        if str(db_path) != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)
        self._lock = threading.Lock()

    def close(self) -> None:
        self._conn.close()

    # --- assessments --------------------------------------------------------------------

    def add_assessment(self, record: AssessmentRecord) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO api_assessments (assessment_id, created_at, payload) VALUES (?, ?, ?)",
                (record.assessment_id, record.created_at.isoformat(), record.model_dump_json()),
            )

    def get_assessment(self, assessment_id: str) -> AssessmentRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM api_assessments WHERE assessment_id = ?", (assessment_id,)
            ).fetchone()
        return AssessmentRecord.model_validate_json(row[0]) if row else None

    def list_assessments(self, limit: int, offset: int) -> list[AssessmentRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload FROM api_assessments ORDER BY created_at DESC, assessment_id "
                "LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [AssessmentRecord.model_validate_json(r[0]) for r in rows]

    # --- decisions (append-only) --------------------------------------------------------

    def add_decision(
        self,
        assessment_id: str,
        recommendation_id: str,
        decision: Decision,
        analyst: str,
        note: str | None,
        recorded_at: datetime | None = None,
    ) -> DecisionRecord:
        when = recorded_at or utc_now()
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO api_decisions (assessment_id, recommendation_id, decision, analyst, "
                "note, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
                (assessment_id, recommendation_id, decision.value, analyst, note, when.isoformat()),
            )
        decision_id = cursor.lastrowid
        if decision_id is None:  # pragma: no cover - sqlite always sets it for INSERT
            raise RuntimeError("SQLite did not return a decision id")
        return DecisionRecord(
            decision_id=decision_id,
            assessment_id=assessment_id,
            recommendation_id=recommendation_id,
            decision=decision,
            analyst=analyst,
            note=note,
            recorded_at=when,
        )

    def decisions(self, assessment_id: str, recommendation_id: str) -> list[DecisionRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT decision_id, decision, analyst, note, recorded_at FROM api_decisions "
                "WHERE assessment_id = ? AND recommendation_id = ? ORDER BY decision_id",
                (assessment_id, recommendation_id),
            ).fetchall()
        return [
            DecisionRecord(
                decision_id=r[0],
                assessment_id=assessment_id,
                recommendation_id=recommendation_id,
                decision=Decision(r[1]),
                analyst=r[2],
                note=r[3],
                recorded_at=datetime.fromisoformat(r[4]),
            )
            for r in rows
        ]
