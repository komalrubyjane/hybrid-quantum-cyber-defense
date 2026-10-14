"""Build the PROCESSED knowledge base from the RAW bundle (deterministic)."""

from __future__ import annotations

import json
from pathlib import Path

from hqc.common.errors import DatasetNotFoundError, MalformedSourceDataError
from hqc.common.provenance import sha256_file
from hqc.mitre.models import KnowledgeBaseData
from hqc.mitre.stix_parser import parse_attack_bundle


def serialize_kb(data: KnowledgeBaseData) -> str:
    """Canonical JSON (stable key order and formatting) for byte-identical rebuilds."""
    return json.dumps(data.model_dump(mode="json"), indent=1, sort_keys=True, ensure_ascii=False)


def build_kb_file(
    raw_path: Path, out_path: Path, version: str, source_url: str | None = None
) -> KnowledgeBaseData:
    """Parse ``raw_path`` and write the processed knowledge base to ``out_path``."""
    if not raw_path.is_file():
        raise DatasetNotFoundError(
            f"RAW ATT&CK bundle not found at {raw_path}. Run scripts/fetch_attack.py first."
        )
    try:
        bundle = json.loads(raw_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise MalformedSourceDataError(f"{raw_path} is not valid JSON") from exc
    data = parse_attack_bundle(
        bundle, expected_version=version, source_url=source_url, source_sha256=sha256_file(raw_path)
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(serialize_kb(data) + "\n", encoding="utf-8")
    return data
