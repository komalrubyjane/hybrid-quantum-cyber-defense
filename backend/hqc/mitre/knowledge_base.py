"""Typed, read-only ATT&CK knowledge base API.

Load the processed representation produced by ``scripts/build_attack_kb.py``::

    kb = AttackKnowledgeBase.load(settings)        # uses settings.attack_version
    kb.get_technique("T1059.004").name             # "Unix Shell" (display only)
    kb.get_mitigations("T1059.004")                # [ATTACKMitigation(...)]

All lookups take ATT&CK IDs. Invalid IDs raise :class:`InvalidTechniqueIdError`,
well-formed but unknown IDs raise :class:`UnknownTechniqueError`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from hqc.common.errors import (
    InvalidTechniqueIdError,
    MalformedSourceDataError,
    UnknownTechniqueError,
    UnsupportedAttackVersionError,
)
from hqc.common.schemas.attack import (
    ATTACKDataComponent,
    ATTACKMitigation,
    ATTACKTactic,
    ATTACKTechnique,
)
from hqc.common.schemas.base import TECHNIQUE_ID_REGEX
from hqc.config import Settings
from hqc.mitre.models import KB_FORMAT_VERSION, KBMetadata, KnowledgeBaseData
from hqc.mitre.paths import processed_kb_path

_TECHNIQUE_RE = re.compile(TECHNIQUE_ID_REGEX)
_MAX_REVOCATION_HOPS = 10


def validate_technique_id(technique_id: str) -> str:
    """Return the ID if it is a syntactically valid ATT&CK technique ID."""
    if not isinstance(technique_id, str) or not _TECHNIQUE_RE.match(technique_id):
        raise InvalidTechniqueIdError(
            f"{technique_id!r} is not a valid ATT&CK technique ID (expected Txxxx or Txxxx.yyy)"
        )
    return technique_id


class AttackKnowledgeBase:
    """In-memory, indexed view over :class:`KnowledgeBaseData`."""

    def __init__(self, data: KnowledgeBaseData) -> None:
        self._data = data
        self._techniques = {t.technique_id: t for t in data.techniques}
        self._tactics = {t.tactic_id: t for t in data.tactics}
        self._mitigations = {m.mitigation_id: m for m in data.mitigations}
        self._components = {c.component_id: c for c in data.data_components}
        children: dict[str, list[str]] = {}
        for t in data.techniques:
            if t.parent_id is not None:
                children.setdefault(t.parent_id, []).append(t.technique_id)
        self._children = {k: sorted(v) for k, v in children.items()}

    # --- construction --------------------------------------------------------------

    @classmethod
    def from_data(cls, data: KnowledgeBaseData) -> AttackKnowledgeBase:
        return cls(data)

    @classmethod
    def from_file(cls, path: Path, expected_version: str | None = None) -> AttackKnowledgeBase:
        """Load a processed ``*.kb.json`` file, validating format and version."""
        if not path.is_file():
            raise UnsupportedAttackVersionError(
                f"No processed ATT&CK knowledge base at {path}. Run: "
                "python scripts/fetch_attack.py && python scripts/build_attack_kb.py"
            )
        try:
            raw: Any = json.loads(path.read_text(encoding="utf-8"))
            data = KnowledgeBaseData.model_validate(raw)
        except (json.JSONDecodeError, ValidationError) as exc:
            raise MalformedSourceDataError(f"Invalid knowledge base file {path}: {exc}") from exc
        if data.metadata.kb_format_version != KB_FORMAT_VERSION:
            raise MalformedSourceDataError(
                f"{path} has KB format {data.metadata.kb_format_version}, "
                f"expected {KB_FORMAT_VERSION}; rebuild it"
            )
        if expected_version is not None and data.metadata.attack_version != expected_version:
            raise UnsupportedAttackVersionError(
                f"{path} contains ATT&CK {data.metadata.attack_version}, "
                f"but {expected_version} was requested"
            )
        return cls(data)

    @classmethod
    def load(cls, settings: Settings) -> AttackKnowledgeBase:
        """Load the knowledge base for ``settings.attack_version``."""
        version = settings.attack_version
        return cls.from_file(processed_kb_path(settings, version), expected_version=version)

    # --- metadata ------------------------------------------------------------------

    def version(self) -> KBMetadata:
        """ATT&CK version and source metadata."""
        return self._data.metadata

    @property
    def data(self) -> KnowledgeBaseData:
        return self._data

    # --- techniques ----------------------------------------------------------------

    def has_technique(self, technique_id: str) -> bool:
        return isinstance(technique_id, str) and technique_id in self._techniques

    def get_technique(self, technique_id: str) -> ATTACKTechnique:
        """Return a technique (active, revoked or deprecated) by ID."""
        validate_technique_id(technique_id)
        try:
            return self._techniques[technique_id]
        except KeyError:
            raise UnknownTechniqueError(
                f"{technique_id} is not in ATT&CK {self._data.metadata.attack_version}"
            ) from None

    def get_techniques(
        self, include_revoked: bool = False, include_deprecated: bool = False
    ) -> list[ATTACKTechnique]:
        """All techniques sorted by ID; active only unless flags are set."""
        return [
            t
            for t in self._data.techniques
            if (include_revoked or not t.revoked) and (include_deprecated or not t.deprecated)
        ]

    def get_subtechniques(self, parent_id: str) -> list[ATTACKTechnique]:
        """Active sub-techniques of a parent technique, sorted by ID."""
        parent = self.get_technique(parent_id)
        if parent.is_subtechnique:
            raise InvalidTechniqueIdError(f"{parent_id} is a sub-technique, not a parent")
        return [
            self._techniques[c]
            for c in self._children.get(parent_id, [])
            if self._techniques[c].is_active
        ]

    def resolve_current(self, technique_id: str) -> ATTACKTechnique | None:
        """Follow ``revoked-by`` links to the current technique.

        Returns None when the technique is deprecated (no replacement) or the chain
        cannot be resolved. This is a DERIVED mapping; callers must record its use.
        """
        current = self.get_technique(technique_id)
        for _ in range(_MAX_REVOCATION_HOPS):
            if current.is_active:
                return current
            if current.revoked_by is None:
                return None
            current = self.get_technique(current.revoked_by)
        return None

    # --- tactics / mitigations / detection ----------------------------------------

    def get_tactics(self, technique_id: str) -> list[ATTACKTactic]:
        """Tactics of a technique in Enterprise matrix order."""
        technique = self.get_technique(technique_id)
        return sorted((self._tactics[t] for t in technique.tactic_ids), key=lambda t: t.order)

    def get_all_tactics(self) -> list[ATTACKTactic]:
        return list(self._data.tactics)

    def get_tactic(self, tactic_id: str) -> ATTACKTactic:
        try:
            return self._tactics[tactic_id]
        except KeyError:
            raise MalformedSourceDataError(f"Unknown tactic {tactic_id!r}") from None

    def get_mitigations(self, technique_id: str) -> list[ATTACKMitigation]:
        """Mitigations linked to a technique by active ``mitigates`` relationships."""
        technique = self.get_technique(technique_id)
        return [self._mitigations[m] for m in technique.mitigation_ids]

    def get_mitigation(self, mitigation_id: str) -> ATTACKMitigation:
        try:
            return self._mitigations[mitigation_id]
        except KeyError:
            raise MalformedSourceDataError(f"Unknown mitigation {mitigation_id!r}") from None

    def get_data_components(self, technique_id: str) -> list[ATTACKDataComponent]:
        """Data components referenced by the technique's detection strategies."""
        technique = self.get_technique(technique_id)
        return [self._components[c] for c in technique.data_component_ids]
