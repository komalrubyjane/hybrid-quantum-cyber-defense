"""Prerequisite checks and concise failure reporting for the runnable evaluation scripts.

A missing local dataset is a setup step, not a data-integrity failure: it gets an actionable
message that names the commands to run. A file that exists but does not match the manifest
checksum is still reported as malformed.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

from hqc.common.errors import DatasetNotFoundError, HQCError, MalformedSourceDataError
from hqc.common.provenance import Manifest, sha256_file
from hqc.config import PROJECT_ROOT, Settings
from hqc.mitre.paths import PROCESSED_ATTACK_FLOW_ARTIFACT_ID, processed_attack_flow_path

ATTACK_FLOW_SETUP = (
    "python scripts/fetch_attack.py && python scripts/build_attack_kb.py && "
    "python scripts/fetch_attack_flow.py && python scripts/build_attack_flow_corpus.py "
    "(see docs/ATTACK_KNOWLEDGE_BASE.md)"
)

#: Exit code for a missing prerequisite (distinct from 1 = a check or evaluation failed).
EXIT_PREREQUISITE = 2


def display_path(path: Path) -> str:
    """Path relative to the project root when possible (no absolute paths in messages)."""
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return path.name


def require_processed_corpus(settings: Settings, manifest: Manifest) -> Path:
    """Return the processed Attack Flow corpus path, verified against the manifest checksum."""
    corpus_path = processed_attack_flow_path(settings)
    if not corpus_path.is_file():
        raise DatasetNotFoundError(
            f"Processed Attack Flow corpus not found ({display_path(corpus_path)}). "
            f"Build it first: {ATTACK_FLOW_SETUP}."
        )
    entry = manifest.get(PROCESSED_ATTACK_FLOW_ARTIFACT_ID)
    if entry is not None and entry.sha256 != sha256_file(corpus_path):
        raise MalformedSourceDataError(
            f"Processed corpus checksum differs from the manifest ({display_path(corpus_path)}). "
            "Rebuild it with python scripts/build_attack_flow_corpus.py."
        )
    return corpus_path


def run_cli(main: Callable[[], int]) -> int:
    """Run a script's ``main``; project errors become one line on stderr instead of a traceback."""
    try:
        return main()
    except DatasetNotFoundError as exc:
        print(f"error: missing prerequisite: {exc}", file=sys.stderr)
        return EXIT_PREREQUISITE
    except HQCError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_PREREQUISITE
