"""Normalised (PROCESSED) knowledge-base representation.

This is derived data: a deterministic transformation of the official RAW STIX bundle.
The file contains no processing timestamp, so the same RAW input always yields a
byte-identical output (the processing time is recorded in the manifest instead).
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from hqc.common.schemas.attack import (
    ATTACKDataComponent,
    ATTACKMitigation,
    ATTACKTactic,
    ATTACKTechnique,
)
from hqc.common.schemas.base import HQCModel, NonEmptyStr

KB_FORMAT_VERSION = "1"
"""Bump when the processed representation or normalisation rules change."""


class KBMetadata(HQCModel):
    """Version and provenance metadata stored inside the processed knowledge base."""

    kb_format_version: NonEmptyStr = KB_FORMAT_VERSION
    attack_version: NonEmptyStr = Field(description="x_mitre_version of the ATT&CK collection")
    attack_spec_version: str | None = None
    domain: Literal["enterprise-attack"] = "enterprise-attack"
    collection_name: NonEmptyStr
    collection_modified: NonEmptyStr
    source_url: str | None = None
    source_sha256: str | None = None
    counts: dict[str, int] = Field(default_factory=dict)
    skipped: dict[str, int] = Field(
        default_factory=dict, description="Source objects intentionally excluded, by reason."
    )


class KBRelationship(HQCModel):
    """A relationship between ATT&CK objects, expressed with ATT&CK IDs."""

    relationship_type: Literal["subtechnique-of", "mitigates", "revoked-by"]
    source_id: NonEmptyStr
    target_id: NonEmptyStr


class KnowledgeBaseData(HQCModel):
    """Complete processed knowledge base (serialised to ``*.kb.json``)."""

    metadata: KBMetadata
    tactics: list[ATTACKTactic]
    techniques: list[ATTACKTechnique]
    mitigations: list[ATTACKMitigation]
    data_components: list[ATTACKDataComponent]
    relationships: list[KBRelationship]
