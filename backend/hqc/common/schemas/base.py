"""Shared base model, constrained types and enumerations for all data contracts."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints

SCHEMA_VERSION = "1.0"
PROBABILITY_SUM_TOLERANCE = 1e-6

TECHNIQUE_ID_REGEX = r"^T\d{4}(\.\d{3})?$"
TACTIC_ID_REGEX = r"^TA\d{4}$"
MITIGATION_ID_REGEX = r"^M\d{4}$"
DETECTION_STRATEGY_ID_REGEX = r"^DET\d{4}$"
DATA_COMPONENT_ID_REGEX = r"^DC\d{4}$"

TechniqueId = Annotated[str, StringConstraints(pattern=TECHNIQUE_ID_REGEX)]
"""ATT&CK technique or sub-technique ID, e.g. ``T1059`` or ``T1059.004``.

Format validation only; existence in the knowledge base is checked by ``hqc.mitre``.
"""
TacticId = Annotated[str, StringConstraints(pattern=TACTIC_ID_REGEX)]
MitigationId = Annotated[str, StringConstraints(pattern=MITIGATION_ID_REGEX)]
DetectionStrategyId = Annotated[str, StringConstraints(pattern=DETECTION_STRATEGY_ID_REGEX)]
DataComponentId = Annotated[str, StringConstraints(pattern=DATA_COMPONENT_ID_REGEX)]
NonEmptyStr = Annotated[str, StringConstraints(min_length=1, strip_whitespace=True)]
Probability = Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]


def _to_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


UTCDatetime = Annotated[AwareDatetime, AfterValidator(_to_utc)]
"""Timezone-aware datetime normalised to UTC. Naive datetimes are rejected."""


def utc_now() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(UTC)


def check_finite_mapping(values: dict[str, float], field_name: str) -> dict[str, float]:
    """Reject NaN / infinite numeric features (they must be handled in preprocessing)."""
    bad = [k for k, v in values.items() if not math.isfinite(v)]
    if bad:
        raise ValueError(f"{field_name} contains non-finite values for keys: {sorted(bad)}")
    return values


class HQCModel(BaseModel):
    """Base for every data contract: strict keys, validated assignment, UTC times."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
        use_enum_values=False,
        ser_json_inf_nan="strings",
    )


class DataOrigin(StrEnum):
    """Where the data came from. Synthetic results must never be presented as real."""

    REAL = "REAL"
    SYNTHETIC = "SYNTHETIC"


class StepProvenance(StrEnum):
    """How an attack-chain step became known."""

    OBSERVED = "OBSERVED"  # directly supported by a security event
    DOCUMENTED = "DOCUMENTED"  # explicitly encoded in curated CTI source data (e.g. Attack Flow)
    INFERRED = "INFERRED"  # derived by reasoning/mapping, not directly observed
    PREDICTED = "PREDICTED"  # model forecast of a future step


class Verdict(StrEnum):
    BENIGN = "BENIGN"
    MALICIOUS = "MALICIOUS"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Disruption(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
