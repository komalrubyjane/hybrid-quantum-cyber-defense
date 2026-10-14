"""Next-technique prediction dataset built from the processed Attack Flow corpus.

Pipeline (the processed corpus itself is never modified):

1. ID NORMALISATION (logged): each source technique ID becomes a vocabulary token.
   - in the vocabulary (active)              -> kept
   - revoked with an active successor        -> replaced via the KB ``revoked-by`` link
   - unknown / deprecated / no successor     -> ``<UNK>``
2. PREDICTION INSTANCES: for every sequence ``t1..tn`` and every position ``i >= 1``,
   the instance is (prefix ``t1..ti``, target ``t(i+1)``). The first technique is never
   a target. Order and repeats are preserved. Instances whose target is ``<UNK>`` are
   dropped and counted (``<UNK>`` may still appear inside prefixes).
3. DEDUPLICATION: instances with the same (document, full prefix, target) are collapsed
   into one unique instance that remembers its raw ``multiplicity``.
4. WEIGHTING (training only; every unique instance counts once in evaluation):
   - DOCUMENT (primary): multiplicity / raw instances of the document -> each document
     has total weight 1.
   - RAW: multiplicity (raw path counts).
   - UNIQUE: 1 per distinct (prefix, target) transition per document.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field

from hqc.common.errors import DatasetNotFoundError, MalformedSourceDataError
from hqc.common.schemas.base import HQCModel, NonEmptyStr
from hqc.mitre.attack_flow_corpus import AttackFlowCorpus
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.prediction.vocabulary import UNK_TOKEN, TechniqueVocabulary

DATASET_ID = "attack-flow-next-technique"
DATASET_FORMAT_VERSION = "1"

TokenKind = Literal["active", "remapped", "unknown"]


class Weighting(StrEnum):
    DOCUMENT = "document"
    RAW = "raw"
    UNIQUE = "unique"


@dataclass(frozen=True)
class NormalizedToken:
    original: str
    token: str
    kind: TokenKind
    reason: str | None = None


class IdNormalizer:
    """Maps source technique IDs to vocabulary tokens using the knowledge base only."""

    def __init__(self, kb: AttackKnowledgeBase, vocabulary: TechniqueVocabulary) -> None:
        if kb.version().attack_version != vocabulary.attack_version:
            raise MalformedSourceDataError(
                f"KB is ATT&CK {kb.version().attack_version} but vocabulary is "
                f"{vocabulary.attack_version}"
            )
        self._kb = kb
        self._vocabulary = vocabulary
        self._cache: dict[str, NormalizedToken] = {}

    def normalize(self, technique_id: str) -> NormalizedToken:
        cached = self._cache.get(technique_id)
        if cached is None:
            cached = self._normalize(technique_id)
            self._cache[technique_id] = cached
        return cached

    def _normalize(self, technique_id: str) -> NormalizedToken:
        if technique_id in self._vocabulary:
            return NormalizedToken(technique_id, technique_id, "active")
        if not self._kb.has_technique(technique_id):
            return NormalizedToken(technique_id, UNK_TOKEN, "unknown", "not in knowledge base")
        current = self._kb.resolve_current(technique_id)
        if current is not None and current.technique_id in self._vocabulary:
            return NormalizedToken(technique_id, current.technique_id, "remapped", "revoked-by")
        technique = self._kb.get_technique(technique_id)
        reason = "deprecated" if technique.deprecated else "revoked without active successor"
        return NormalizedToken(technique_id, UNK_TOKEN, "unknown", reason)


class RemapRecord(HQCModel):
    original: NonEmptyStr
    replacement: NonEmptyStr
    occurrences: int = Field(ge=0, description="Occurrences across all included sequences.")
    documents: list[str]


class UnknownRecord(HQCModel):
    original: NonEmptyStr
    reason: NonEmptyStr
    occurrences: int = Field(ge=0)
    documents: list[str]


class DocumentStats(HQCModel):
    document_id: NonEmptyStr
    source_group: NonEmptyStr
    sequences: int
    raw_instances: int
    unique_instances: int
    unk_targets_dropped: int


class DatasetStats(HQCModel):
    """Measured statistics of the constructed dataset (reported in every run)."""

    dataset_id: NonEmptyStr = DATASET_ID
    dataset_format_version: NonEmptyStr = DATASET_FORMAT_VERSION
    corpus_version: NonEmptyStr
    attack_version: NonEmptyStr
    vocabulary_version: NonEmptyStr
    active_techniques: int
    documents: int
    source_groups: int
    groups_without_instances: list[str]
    sequences: int
    raw_instances: int
    unique_instances: int
    collapsed_duplicates: int
    collapse_percentage: float
    unk_targets_dropped: int
    unknown_ids: list[UnknownRecord]
    remapped_ids: list[RemapRecord]
    revoked_ids_remapped: int
    remap_occurrences: int
    largest_documents_share: dict[str, float] = Field(
        description="Share of raw instances contributed by the 4 largest documents."
    )
    per_document: list[DocumentStats]


@dataclass(frozen=True)
class PredictionInstance:
    """One unique (document, full prefix, target) instance."""

    instance_id: int
    document_id: str
    source_group: str
    prefix: tuple[str, ...]
    target: str
    multiplicity: int


@dataclass(frozen=True)
class NormalizedSequence:
    """One source path after ID normalisation (order and repeats preserved)."""

    sequence_id: str
    document_id: str
    source_group: str
    tokens: tuple[str, ...]


@dataclass(frozen=True)
class WeightedInstance:
    prefix: tuple[str, ...]
    target: str
    weight: float


class PredictionDataset:
    """Unique prediction instances plus provenance and statistics."""

    def __init__(
        self,
        instances: list[PredictionInstance],
        stats: DatasetStats,
        doc_raw: dict[str, int],
        sequences: list[NormalizedSequence] | None = None,
    ) -> None:
        self.instances = instances
        self.sequences = sequences or []
        self.stats = stats
        self._doc_raw = doc_raw
        self.group_of_document = {i.document_id: i.source_group for i in instances}
        for doc in stats.per_document:
            self.group_of_document[doc.document_id] = doc.source_group

    @property
    def groups(self) -> list[str]:
        return sorted(set(self.group_of_document.values()))

    def instances_by_group(self) -> dict[str, list[PredictionInstance]]:
        grouped: dict[str, list[PredictionInstance]] = {g: [] for g in self.groups}
        for instance in self.instances:
            grouped[instance.source_group].append(instance)
        return grouped

    def weight(self, instance: PredictionInstance, weighting: Weighting) -> float:
        if weighting is Weighting.DOCUMENT:
            return instance.multiplicity / self._doc_raw[instance.document_id]
        if weighting is Weighting.RAW:
            return float(instance.multiplicity)
        return 1.0

    def weighted(
        self, instances: list[PredictionInstance], weighting: Weighting
    ) -> list[WeightedInstance]:
        return [WeightedInstance(i.prefix, i.target, self.weight(i, weighting)) for i in instances]

    def weighting_totals(self) -> dict[str, float]:
        return {
            w.value: round(sum(self.weight(i, w) for i in self.instances), 6) for w in Weighting
        }


def build_dataset(
    corpus: AttackFlowCorpus, kb: AttackKnowledgeBase, vocabulary: TechniqueVocabulary
) -> PredictionDataset:
    """Construct the dataset from the INCLUDED documents of a processed corpus."""
    normalizer = IdNormalizer(kb, vocabulary)
    remap_counts: Counter[str] = Counter()
    unknown_counts: Counter[str] = Counter()
    remap_docs: dict[str, set[str]] = defaultdict(set)
    unknown_docs: dict[str, set[str]] = defaultdict(set)
    multiplicity: dict[tuple[str, tuple[str, ...], str], int] = {}
    first_seen: list[tuple[str, str, tuple[str, ...], str]] = []
    normalized_sequences: list[NormalizedSequence] = []
    doc_stats: list[DocumentStats] = []
    doc_raw: dict[str, int] = {}
    total_sequences = 0
    total_dropped = 0

    documents = corpus.included_documents
    if not documents:
        raise DatasetNotFoundError("The processed corpus contains no included documents")
    for document in documents:
        raw = 0
        dropped = 0
        unique_before = len(multiplicity)
        for sequence in document.sequences:
            total_sequences += 1
            tokens: list[str] = []
            for technique_id in sequence.technique_ids:
                norm = normalizer.normalize(technique_id)
                if norm.kind == "remapped":
                    remap_counts[technique_id] += 1
                    remap_docs[technique_id].add(document.document_id)
                elif norm.kind == "unknown":
                    unknown_counts[technique_id] += 1
                    unknown_docs[technique_id].add(document.document_id)
                tokens.append(norm.token)
            normalized_sequences.append(
                NormalizedSequence(
                    sequence.sequence_id, document.document_id, document.source_group, tuple(tokens)
                )
            )
            for i in range(1, len(tokens)):
                target = tokens[i]
                if target == UNK_TOKEN:
                    dropped += 1
                    continue
                raw += 1
                key = (document.document_id, tuple(tokens[:i]), target)
                if key not in multiplicity:
                    multiplicity[key] = 0
                    first_seen.append((document.source_group, *key))
                multiplicity[key] += 1
        doc_raw[document.document_id] = raw
        total_dropped += dropped
        doc_stats.append(
            DocumentStats(
                document_id=document.document_id,
                source_group=document.source_group,
                sequences=len(document.sequences),
                raw_instances=raw,
                unique_instances=len(multiplicity) - unique_before,
                unk_targets_dropped=dropped,
            )
        )

    instances = [
        PredictionInstance(
            instance_id=n,
            document_id=doc,
            source_group=group,
            prefix=prefix,
            target=target,
            multiplicity=multiplicity[(doc, prefix, target)],
        )
        for n, (group, doc, prefix, target) in enumerate(first_seen)
    ]
    raw_total = sum(doc_raw.values())
    groups = sorted({d.source_group for d in documents})
    groups_with_instances = {i.source_group for i in instances}
    largest = sorted(doc_stats, key=lambda d: (-d.raw_instances, d.document_id))[:4]

    def unknown_reason(tid: str) -> str:
        return normalizer.normalize(tid).reason or "unknown"

    stats = DatasetStats(
        corpus_version=corpus.summary.source_version,
        attack_version=vocabulary.attack_version,
        vocabulary_version=vocabulary.vocabulary_version,
        active_techniques=vocabulary.size - 2,
        documents=len(documents),
        source_groups=len(groups),
        groups_without_instances=[g for g in groups if g not in groups_with_instances],
        sequences=total_sequences,
        raw_instances=raw_total,
        unique_instances=len(instances),
        collapsed_duplicates=raw_total - len(instances),
        collapse_percentage=round(100.0 * (raw_total - len(instances)) / raw_total, 3)
        if raw_total
        else 0.0,
        unk_targets_dropped=total_dropped,
        unknown_ids=[
            UnknownRecord(
                original=t,
                reason=unknown_reason(t),
                occurrences=unknown_counts[t],
                documents=sorted(unknown_docs[t]),
            )
            for t in sorted(unknown_counts)
        ],
        remapped_ids=[
            RemapRecord(
                original=t,
                replacement=normalizer.normalize(t).token,
                occurrences=remap_counts[t],
                documents=sorted(remap_docs[t]),
            )
            for t in sorted(remap_counts)
        ],
        revoked_ids_remapped=len(remap_counts),
        remap_occurrences=sum(remap_counts.values()),
        largest_documents_share={
            d.document_id: round(d.raw_instances / raw_total, 4) if raw_total else 0.0
            for d in largest
        },
        per_document=doc_stats,
    )
    return PredictionDataset(instances, stats, doc_raw, normalized_sequences)


def load_corpus(path: Path) -> AttackFlowCorpus:
    """Load the processed Attack Flow corpus (read-only)."""
    if not path.is_file():
        raise DatasetNotFoundError(
            f"Processed Attack Flow corpus not found at {path}. "
            "Run scripts/fetch_attack_flow.py and scripts/build_attack_flow_corpus.py."
        )
    try:
        return AttackFlowCorpus.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise MalformedSourceDataError(f"Invalid processed corpus {path}: {exc}") from exc
