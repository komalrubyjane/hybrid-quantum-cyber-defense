"""SQLite implementation of :class:`~hqc.storage.base.Store` (standard library only)."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from types import TracebackType

from pydantic import BaseModel

from hqc.common.errors import RecordNotFoundError, StorageError
from hqc.common.logging import get_logger
from hqc.common.schemas import SCHEMA_VERSION
from hqc.common.schemas.base import utc_now
from hqc.storage.base import COLLECTION_SPECS, Collection, CollectionSpec

log = get_logger(__name__)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS records (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    collection     TEXT NOT NULL,
    record_key     TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    stored_at      TEXT NOT NULL,
    payload        TEXT NOT NULL,
    UNIQUE (collection, record_key)
);
"""


class SQLiteStore:
    """Typed record store backed by a single SQLite table.

    Use ``SQLiteStore(":memory:")`` for tests. A single connection guarded by a lock
    is shared across threads (sufficient for the local MVP).
    """

    def __init__(self, db_path: Path | str) -> None:
        self._path = str(db_path)
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL" if self._path != ":memory:" else "SELECT 1")
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    @staticmethod
    def _spec(collection: Collection) -> CollectionSpec:
        return COLLECTION_SPECS[Collection(collection)]

    def put(self, collection: Collection, record: BaseModel) -> str:
        spec = self._spec(collection)
        if not isinstance(record, spec.types):
            expected = ", ".join(t.__name__ for t in spec.types)
            raise TypeError(f"{collection} expects {expected}; got {type(record).__name__}")
        key = spec.key(record)
        payload = record.model_dump_json()
        with self._lock:
            if spec.immutable and self._exists(collection, key):
                raise StorageError(f"{collection} record {key!r} already exists (write-once).")
            self._conn.execute(
                """
                INSERT INTO records (collection, record_key, schema_version, stored_at, payload)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (collection, record_key)
                DO UPDATE SET payload = excluded.payload,
                              schema_version = excluded.schema_version,
                              stored_at = excluded.stored_at
                """,
                (str(collection), key, SCHEMA_VERSION, utc_now().isoformat(), payload),
            )
            self._conn.commit()
        log.debug("record stored", extra={"stage": "storage", "collection": str(collection)})
        return key

    def _exists(self, collection: Collection, key: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM records WHERE collection = ? AND record_key = ?",
            (str(collection), key),
        ).fetchone()
        return row is not None

    def get(self, collection: Collection, key: str) -> BaseModel:
        spec = self._spec(collection)
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM records WHERE collection = ? AND record_key = ?",
                (str(collection), key),
            ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"{collection}/{key}")
        record: BaseModel = spec.adapter.validate_json(row[0])
        return record

    def list(self, collection: Collection, limit: int = 100, offset: int = 0) -> list[BaseModel]:
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        spec = self._spec(collection)
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload FROM records WHERE collection = ? ORDER BY seq LIMIT ? OFFSET ?",
                (str(collection), limit, offset),
            ).fetchall()
        return [spec.adapter.validate_json(r[0]) for r in rows]

    def count(self, collection: Collection) -> int:
        self._spec(collection)
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM records WHERE collection = ?", (str(collection),)
            ).fetchone()
        return int(row[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> SQLiteStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
