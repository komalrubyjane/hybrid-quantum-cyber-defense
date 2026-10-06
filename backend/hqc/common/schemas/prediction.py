"""Attack-chain prediction contracts. Everything here is PREDICTED, never observed."""

from __future__ import annotations

import math
from typing import Literal

from pydantic import Field, field_validator, model_validator

from hqc.common.schemas.base import (
    PROBABILITY_SUM_TOLERANCE,
    HQCModel,
    NonEmptyStr,
    Probability,
    TechniqueId,
    UTCDatetime,
    utc_now,
)


class NextTechniqueProbability(HQCModel):
    technique_id: TechniqueId
    probability: Probability


class PredictedPath(HQCModel):
    """A candidate future path produced by beam search."""

    technique_ids: list[TechniqueId] = Field(min_length=1)
    probability: Probability = Field(description="Joint probability of the continuation.")
    cumulative_log_score: float = Field(le=0.0, allow_inf_nan=False)
    length: int = Field(ge=1)

    @model_validator(mode="after")
    def _consistent(self) -> PredictedPath:
        if self.length != len(self.technique_ids):
            raise ValueError("length must equal len(technique_ids).")
        return self


class PredictionResult(HQCModel):
    """Next-step distribution and multi-step paths for an observed prefix."""

    prediction_id: NonEmptyStr
    chain_id: str | None = None
    observed_prefix: list[TechniqueId] = Field(min_length=1)
    next_step: list[NextTechniqueProbability] = Field(default_factory=list)
    paths: list[PredictedPath] = Field(default_factory=list)
    horizon: int = Field(ge=1)
    model_id: NonEmptyStr
    vocabulary_version: NonEmptyStr
    attack_version: NonEmptyStr
    provenance: Literal["PREDICTED"] = "PREDICTED"
    created_at: UTCDatetime = Field(default_factory=utc_now)

    @field_validator("next_step")
    @classmethod
    def _distribution_valid(
        cls, value: list[NextTechniqueProbability]
    ) -> list[NextTechniqueProbability]:
        ids = [item.technique_id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("next_step contains duplicate technique IDs.")
        total = math.fsum(item.probability for item in value)
        if total > 1.0 + PROBABILITY_SUM_TOLERANCE:
            raise ValueError(f"next_step probabilities sum to {total:.6f} > 1.")
        probs = [item.probability for item in value]
        if probs != sorted(probs, reverse=True):
            raise ValueError("next_step must be sorted by descending probability.")
        return value

    @model_validator(mode="after")
    def _paths_within_horizon(self) -> PredictionResult:
        if any(p.length > self.horizon for p in self.paths):
            raise ValueError("A predicted path is longer than the horizon.")
        return self
