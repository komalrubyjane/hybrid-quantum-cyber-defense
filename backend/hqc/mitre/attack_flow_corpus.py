"""Build the processed Attack Flow corpus and a KB-coverage summary.

The processed corpus keeps technique IDs exactly as written in the source. Mapping
revoked IDs to their replacements is a separate, explicit DERIVED step (not done here);
the summary reports which IDs would need it.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from pydantic import Field

from hqc.common.errors import DatasetNotFoundError
from hqc.common.schemas.base import HQCModel, NonEmptyStr
from hqc.mitre.attack_flow import (
    DEFAULT_EXCLUDED_SCOPES,
    DEFAULT_MAX_PATHS_PER_DOCUMENT,
    PARSER_VERSION,
    AttackFlowDocument,
    FlowDocumentStats,
    load_attack_flow_file,
)
from hqc.mitre.knowledge_base import AttackKnowledgeBase


class TechniqueCoverage(HQCModel):
    """How the corpus' ATT&CK technique IDs relate to the loaded knowledge base."""

    attack_version: NonEmptyStr
    active: list[str] = Field(default_factory=list)
    revoked: dict[str, str | None] = Field(
        default_factory=dict, description="revoked ID -> replacement (revoked-by)"
    )
    deprecated: list[str] = Field(default_factory=list)
    unknown: list[str] = Field(
        default_factory=list, description="Well-formed IDs absent from this KB (e.g. ICS)."
    )


class DocumentSummary(HQCModel):
    document_id: NonEmptyStr
    source_group: NonEmptyStr
    flow_name: NonEmptyStr
    scope: str | None
    excluded: bool
    source_sha256: NonEmptyStr
    sequences: int
    stats: FlowDocumentStats


class CorpusSummary(HQCModel):
    """Small, tracked summary of the processed corpus (counts are measured, not estimated)."""

    source_version: NonEmptyStr
    parser_version: NonEmptyStr = PARSER_VERSION
    excluded_scopes: list[str]
    max_paths_per_document: int
    documents_total: int
    documents_included: int
    source_groups: int
    sequences: int
    unique_attack_technique_ids: int
    actions_by_kind: dict[str, int]
    sequence_length: dict[str, float]
    coverage: TechniqueCoverage | None = None
    documents: list[DocumentSummary]


class AttackFlowCorpus(HQCModel):
    """Processed corpus: every parsed document (included and excluded) plus summary."""

    summary: CorpusSummary
    documents: list[AttackFlowDocument]

    @property
    def included_documents(self) -> list[AttackFlowDocument]:
        return [d for d in self.documents if not d.excluded]


def technique_coverage(technique_ids: set[str], kb: AttackKnowledgeBase) -> TechniqueCoverage:
    coverage = TechniqueCoverage(attack_version=kb.version().attack_version)
    for tid in sorted(technique_ids):
        if not kb.has_technique(tid):
            coverage.unknown.append(tid)
            continue
        technique = kb.get_technique(tid)
        if technique.revoked:
            coverage.revoked[tid] = technique.revoked_by
        elif technique.deprecated:
            coverage.deprecated.append(tid)
        else:
            coverage.active.append(tid)
    return coverage


def build_corpus(
    stix_dir: Path,
    source_version: str,
    kb: AttackKnowledgeBase | None = None,
    max_paths: int = DEFAULT_MAX_PATHS_PER_DOCUMENT,
    excluded_scopes: frozenset[str] = DEFAULT_EXCLUDED_SCOPES,
) -> AttackFlowCorpus:
    """Parse every ``*.json`` flow in ``stix_dir`` (file-name order for determinism)."""
    files = sorted(stix_dir.glob("*.json"))
    if not files:
        raise DatasetNotFoundError(
            f"No Attack Flow STIX files in {stix_dir}. Run scripts/fetch_attack_flow.py first."
        )
    documents = [
        load_attack_flow_file(f, source_version, max_paths, excluded_scopes) for f in files
    ]
    included = [d for d in documents if not d.excluded]
    sequences = [s for d in included for s in d.sequences]
    technique_ids = {a.technique_id for d in included for a in d.actions if a.technique_id}
    kinds: Counter[str] = Counter(a.technique_kind for d in included for a in d.actions)
    lengths = sorted(len(s.steps) for s in sequences)
    summary = CorpusSummary(
        source_version=source_version,
        excluded_scopes=sorted(excluded_scopes),
        max_paths_per_document=max_paths,
        documents_total=len(documents),
        documents_included=len(included),
        source_groups=len({d.source_group for d in included}),
        sequences=len(sequences),
        unique_attack_technique_ids=len(technique_ids),
        actions_by_kind=dict(sorted(kinds.items())),
        sequence_length={
            "min": float(lengths[0]) if lengths else 0.0,
            "median": float(lengths[len(lengths) // 2]) if lengths else 0.0,
            "max": float(lengths[-1]) if lengths else 0.0,
            "mean": round(sum(lengths) / len(lengths), 3) if lengths else 0.0,
        },
        coverage=technique_coverage(technique_ids, kb) if kb is not None else None,
        documents=[
            DocumentSummary(
                document_id=d.document_id,
                source_group=d.source_group,
                flow_name=d.flow_name,
                scope=d.scope,
                excluded=d.excluded,
                source_sha256=d.source_sha256,
                sequences=len(d.sequences),
                stats=d.stats,
            )
            for d in documents
        ],
    )
    return AttackFlowCorpus(summary=summary, documents=documents)


def write_json(model: HQCModel, path: Path, compact: bool = False) -> None:
    """Canonical JSON (sorted keys) for byte-identical rebuilds; ``compact`` drops whitespace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = model.model_dump(mode="json")
    if compact:
        text = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    else:
        text = json.dumps(payload, indent=1, sort_keys=True, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8")
