"""Technique context for Milestone 7: activity, tactics and mitigations of ATT&CK techniques.

``is_active`` is decided by the committed ATT&CK 19.2 technique vocabulary (the active,
non-revoked, non-deprecated techniques). Tactics (in Enterprise-matrix order) and
mitigations come from the local ATT&CK knowledge base. No relationship is invented: an ID
the catalog does not know has no tactics and no mitigations.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from hqc.common.schemas.attack import ATTACKTactic
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.prediction.vocabulary import SPECIAL_TOKENS, UNK_TOKEN, TechniqueVocabulary


class TechniqueCatalog(Protocol):
    @property
    def attack_version(self) -> str: ...

    @property
    def tactic_count(self) -> int:
        """Number of tactics in the Enterprise matrix (for progression scaling)."""
        ...

    def is_active(self, technique_id: str) -> bool: ...

    def tactics(self, technique_id: str) -> list[ATTACKTactic]:
        """Tactics of the technique in matrix order; [] if unknown."""
        ...

    def mitigation_ids(self, technique_id: str) -> list[str]: ...


def vocabulary_token(technique_id: str, vocabulary: TechniqueVocabulary) -> str:
    """The prediction-context token: the ID if it is an active vocabulary technique, else <UNK>."""
    if technique_id in SPECIAL_TOKENS or technique_id not in vocabulary:
        return UNK_TOKEN
    return technique_id


class KnowledgeBaseCatalog:
    """Catalog backed by the ATT&CK knowledge base and the committed vocabulary."""

    def __init__(self, kb: AttackKnowledgeBase, vocabulary: TechniqueVocabulary) -> None:
        if kb.version().attack_version != vocabulary.attack_version:
            raise ValueError("Knowledge base and vocabulary ATT&CK versions differ")
        self._kb = kb
        self._vocabulary = vocabulary

    @property
    def attack_version(self) -> str:
        return self._vocabulary.attack_version

    @property
    def tactic_count(self) -> int:
        return len(self._kb.get_all_tactics())

    def is_active(self, technique_id: str) -> bool:
        return vocabulary_token(technique_id, self._vocabulary) != UNK_TOKEN

    def tactics(self, technique_id: str) -> list[ATTACKTactic]:
        if not self._kb.has_technique(technique_id):
            return []
        return self._kb.get_tactics(technique_id)

    def mitigation_ids(self, technique_id: str) -> list[str]:
        if not self._kb.has_technique(technique_id):
            return []
        return sorted(m.mitigation_id for m in self._kb.get_mitigations(technique_id))


@dataclass
class StaticCatalog:
    """Explicit in-memory catalog (tests, or a documented subset when the KB is absent)."""

    version: str
    active: frozenset[str]
    technique_tactics: Mapping[str, Sequence[ATTACKTactic]] = field(default_factory=dict)
    technique_mitigations: Mapping[str, Sequence[str]] = field(default_factory=dict)
    n_tactics: int = 15

    @property
    def attack_version(self) -> str:
        return self.version

    @property
    def tactic_count(self) -> int:
        return self.n_tactics

    def is_active(self, technique_id: str) -> bool:
        return technique_id in self.active

    def tactics(self, technique_id: str) -> list[ATTACKTactic]:
        return sorted(self.technique_tactics.get(technique_id, ()), key=lambda t: t.order)

    def mitigation_ids(self, technique_id: str) -> list[str]:
        return sorted(self.technique_mitigations.get(technique_id, ()))
