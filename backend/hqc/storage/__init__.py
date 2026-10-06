"""Storage abstraction (SQLite for the MVP)."""

from hqc.storage.base import COLLECTION_SPECS, Collection, Store
from hqc.storage.sqlite_store import SQLiteStore

__all__ = ["COLLECTION_SPECS", "Collection", "SQLiteStore", "Store"]
