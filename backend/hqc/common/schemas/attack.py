"""ATT&CK technique, technique candidates, attack steps and attack chains."""

from __future__ import annotations

from itertools import pairwise

from pydantic import Field, model_validator

from hqc.common.schemas.base import (
    DataComponentId,
    DataOrigin,
    DetectionStrategyId,
    HQCModel,
    MitigationId,
    NonEmptyStr,
    Probability,
    StepProvenance,
    TacticId,
    TechniqueId,
    UTCDatetime,
    utc_now,
)


class ATTACKTactic(HQCModel):
    """An ATT&CK tactic. ``order`` is its position in the Enterprise matrix."""

    tactic_id: TacticId
    name: NonEmptyStr
    shortname: NonEmptyStr
    order: int = Field(ge=0)
    description: str | None = None


class ATTACKMitigation(HQCModel):
    """An ATT&CK mitigation (course-of-action with an ``M####`` ID)."""

    mitigation_id: MitigationId
    name: NonEmptyStr
    description: str | None = None
    technique_ids: list[TechniqueId] = Field(default_factory=list)


class ATTACKDataComponent(HQCModel):
    """An ATT&CK data component (``DC####``) referenced by detection analytics."""

    component_id: DataComponentId
    name: NonEmptyStr


class ATTACKTechnique(HQCModel):
    """One ATT&CK (sub-)technique as stored in the local knowledge base.

    Since ATT&CK v18, data sources are deprecated; detection coverage is expressed as
    detection strategies (``DET####``) whose analytics reference data components
    (``DC####``). Both are recorded here instead of the legacy data-source list.
    """

    technique_id: TechniqueId
    name: NonEmptyStr
    tactic_ids: list[TacticId] = Field(default_factory=list)
    is_subtechnique: bool
    parent_id: TechniqueId | None = None
    description: str | None = None
    platforms: list[str] = Field(default_factory=list)
    mitigation_ids: list[MitigationId] = Field(default_factory=list)
    detection_strategy_ids: list[DetectionStrategyId] = Field(default_factory=list)
    data_component_ids: list[DataComponentId] = Field(default_factory=list)
    deprecated: bool = False
    revoked: bool = False
    revoked_by: TechniqueId | None = None
    stix_id: str | None = None
    url: str | None = None
    attack_version: NonEmptyStr

    @property
    def is_active(self) -> bool:
        """Neither revoked nor deprecated."""
        return not (self.revoked or self.deprecated)

    @model_validator(mode="after")
    def _hierarchy_consistent(self) -> ATTACKTechnique:
        dotted = "." in self.technique_id
        if self.is_subtechnique != dotted:
            raise ValueError("is_subtechnique must match the ID format (Txxxx.yyy).")
        if self.is_subtechnique:
            expected_parent = self.technique_id.split(".", 1)[0]
            if self.parent_id != expected_parent:
                raise ValueError(f"parent_id must be {expected_parent} for {self.technique_id}.")
        elif self.parent_id is not None:
            raise ValueError("A parent technique cannot have parent_id.")
        return self


class TechniqueCandidate(HQCModel):
    """A candidate technique produced by mapping, with confidence and evidence.

    A single network flow rarely identifies a technique uniquely, so mappings
    produce one or more candidates rather than a single answer.
    """

    technique_id: TechniqueId
    confidence: Probability
    evidence: list[str] = Field(default_factory=list)
    mapping_source: NonEmptyStr = Field(description="e.g. 'mapping:cicids2017@1'.")


class AttackStep(HQCModel):
    """One step of an attack chain."""

    technique_id: TechniqueId
    tactic_id: TacticId | None = None
    timestamp: UTCDatetime | None = Field(
        default=None, description="Event time. May be absent for knowledge-base sequences."
    )
    event_id: str | None = None
    confidence: Probability
    source: NonEmptyStr = Field(description="Origin of the step, e.g. a mapping table or flow.")
    provenance: StepProvenance
    alternative_candidates: list[TechniqueCandidate] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _observed_needs_event(self) -> AttackStep:
        if self.provenance is StepProvenance.OBSERVED and not self.event_id:
            raise ValueError("OBSERVED steps must reference the security event (event_id).")
        if self.provenance is StepProvenance.PREDICTED and self.event_id:
            raise ValueError("PREDICTED steps cannot reference an observed event.")
        return self


class AttackChain(HQCModel):
    """An ordered sequence of attack steps.

    Order is significant and is never re-sorted: if timestamps are present they must
    already be non-decreasing, otherwise validation fails.
    """

    chain_id: NonEmptyStr
    entity_ids: list[NonEmptyStr] = Field(default_factory=list)
    steps: list[AttackStep] = Field(min_length=1)
    data_origin: DataOrigin
    attack_version: NonEmptyStr
    created_at: UTCDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _chronological(self) -> AttackChain:
        times = [s.timestamp for s in self.steps if s.timestamp is not None]
        if any(later < earlier for earlier, later in pairwise(times)):
            raise ValueError("AttackChain steps must be in non-decreasing timestamp order.")
        if any(s.provenance is StepProvenance.PREDICTED for s in self.steps):
            raise ValueError("Predicted steps belong in PredictionResult, not AttackChain.")
        return self

    @property
    def technique_ids(self) -> list[str]:
        """Technique IDs in chain order."""
        return [s.technique_id for s in self.steps]
