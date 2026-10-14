"""Deterministic ATT&CK technique vocabulary shared by every prediction component.

Contents: the special tokens ``<PAD>`` (index 0, sequence padding for batched models)
and ``<UNK>`` (index 1, any ID outside the vocabulary), followed by every ACTIVE
(non-revoked, non-deprecated) Enterprise technique and sub-technique of one ATT&CK
version, in ascending technique-ID order.

Why built from the knowledge base and not from the Attack Flow corpus: the vocabulary
must not depend on which documents land in training or evaluation (no leakage), and it
must be identical for every model. ID order is used only to assign stable indices; it
says nothing about attack chronology.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Final, Literal

from pydantic import ConfigDict, Field, ValidationError, model_validator

from hqc.common.errors import InvalidTechniqueIdError, MalformedSourceDataError
from hqc.common.schemas.base import HQCModel, NonEmptyStr
from hqc.mitre.knowledge_base import AttackKnowledgeBase, validate_technique_id

VOCABULARY_FORMAT_VERSION: Final = "1"
PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"
SPECIAL_TOKENS: tuple[str, ...] = (PAD_TOKEN, UNK_TOKEN)
VOCABULARY_SCOPE: Final = "attack-enterprise-active-techniques"


def _content_hash(tokens: Sequence[str]) -> str:
    return hashlib.sha256("\n".join(tokens).encode("utf-8")).hexdigest()


class TechniqueVocabulary(HQCModel):
    """Versioned, immutable technique-ID <-> index mapping."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    format_version: Literal["1"] = VOCABULARY_FORMAT_VERSION
    vocabulary_version: NonEmptyStr
    attack_version: NonEmptyStr
    attack_kb_source_sha256: str | None = None
    scope: Literal["attack-enterprise-active-techniques"] = VOCABULARY_SCOPE
    special_tokens: dict[str, int]
    index_to_token: list[str] = Field(min_length=len(SPECIAL_TOKENS))
    token_to_index: dict[str, int]
    content_sha256: NonEmptyStr

    @model_validator(mode="after")
    def _consistent(self) -> TechniqueVocabulary:
        tokens = self.index_to_token
        if tuple(tokens[: len(SPECIAL_TOKENS)]) != SPECIAL_TOKENS:
            raise ValueError(f"First tokens must be {SPECIAL_TOKENS}")
        if self.special_tokens != {t: i for i, t in enumerate(SPECIAL_TOKENS)}:
            raise ValueError("special_tokens does not match the token list")
        if self.token_to_index != {t: i for i, t in enumerate(tokens)}:
            raise ValueError("token_to_index and index_to_token disagree (or duplicates)")
        technique_tokens = tokens[len(SPECIAL_TOKENS) :]
        for token in technique_tokens:
            validate_technique_id(token)
        if technique_tokens != sorted(technique_tokens):
            raise ValueError("Technique tokens must be in ascending ID order")
        if self.content_sha256 != _content_hash(tokens):
            raise ValueError("content_sha256 does not match the token list")
        if not self.vocabulary_version.endswith(self.content_sha256[:12]):
            raise ValueError("vocabulary_version must end with the content hash prefix")
        return self

    # --- construction ---------------------------------------------------------------

    @classmethod
    def from_technique_ids(
        cls,
        technique_ids: Iterable[str],
        attack_version: str,
        attack_kb_source_sha256: str | None = None,
    ) -> TechniqueVocabulary:
        ids = sorted({validate_technique_id(t) for t in technique_ids})
        tokens = [*SPECIAL_TOKENS, *ids]
        digest = _content_hash(tokens)
        return cls(
            vocabulary_version=f"v{VOCABULARY_FORMAT_VERSION}-attack-{attack_version}-{digest[:12]}",
            attack_version=attack_version,
            attack_kb_source_sha256=attack_kb_source_sha256,
            special_tokens={t: i for i, t in enumerate(SPECIAL_TOKENS)},
            index_to_token=tokens,
            token_to_index={t: i for i, t in enumerate(tokens)},
            content_sha256=digest,
        )

    @classmethod
    def from_knowledge_base(cls, kb: AttackKnowledgeBase) -> TechniqueVocabulary:
        meta = kb.version()
        return cls.from_technique_ids(
            (t.technique_id for t in kb.get_techniques()),
            attack_version=meta.attack_version,
            attack_kb_source_sha256=meta.source_sha256,
        )

    # --- persistence ----------------------------------------------------------------

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(self.model_dump(mode="json"), indent=1, sort_keys=False)
        path.write_text(text + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path, expected_attack_version: str | None = None) -> TechniqueVocabulary:
        try:
            vocab = cls.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError) as exc:
            raise MalformedSourceDataError(f"Invalid vocabulary file {path}: {exc}") from exc
        if expected_attack_version and vocab.attack_version != expected_attack_version:
            raise MalformedSourceDataError(
                f"Vocabulary {path} is for ATT&CK {vocab.attack_version}, "
                f"expected {expected_attack_version}"
            )
        return vocab

    # --- lookup -------------------------------------------------------------------

    @property
    def size(self) -> int:
        return len(self.index_to_token)

    @property
    def pad_index(self) -> int:
        return self.special_tokens[PAD_TOKEN]

    @property
    def unk_index(self) -> int:
        return self.special_tokens[UNK_TOKEN]

    def __contains__(self, token: object) -> bool:
        return isinstance(token, str) and token in self.token_to_index

    def index_of(self, technique_id: str, on_unknown: Literal["unk", "error"] = "unk") -> int:
        """Index of a technique ID. Malformed IDs always raise."""
        validate_technique_id(technique_id)
        if technique_id in self.token_to_index:
            return self.token_to_index[technique_id]
        if on_unknown == "error":
            raise InvalidTechniqueIdError(
                f"{technique_id} is not in vocabulary {self.vocabulary_version}"
            )
        return self.unk_index

    def encode(
        self, technique_ids: Sequence[str], on_unknown: Literal["unk", "error"] = "unk"
    ) -> list[int]:
        """Encode a sequence, preserving its order exactly."""
        return [self.index_of(t, on_unknown) for t in technique_ids]

    def decode(self, indices: Sequence[int]) -> list[str]:
        """Map indices back to tokens; negative or out-of-range indices raise."""
        bad = [i for i in indices if not isinstance(i, int) or not 0 <= i < self.size]
        if bad:
            raise ValueError(f"Indices {bad} out of range for vocabulary of size {self.size}")
        return [self.index_to_token[i] for i in indices]
