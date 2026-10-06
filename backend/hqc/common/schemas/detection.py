"""Detection contracts: classical decision plus optional quantum second opinion."""

from __future__ import annotations

from pydantic import Field, model_validator

from hqc.common.schemas.base import HQCModel, NonEmptyStr, Probability, Verdict


def confidence_from_probability(p_malicious: float) -> float:
    """Binary confidence: distance of the decision from a coin flip, in [0.5, 1]."""
    return max(p_malicious, 1.0 - p_malicious)


class QuantumOpinion(HQCModel):
    """Result of the quantum second-opinion classifier for one event.

    The quantum opinion never overrides the classical verdict automatically;
    disagreement is a signal to collect additional evidence.
    """

    gate_triggered: bool = Field(description="Whether the QuantumGate sent this event onward.")
    verdict: Verdict | None = None
    p_malicious: Probability | None = None
    confidence: Probability | None = None
    backend: str | None = Field(default=None, description="Simulator identifier.")
    feature_map: str | None = None
    latency_ms: float | None = Field(default=None, ge=0.0)

    @model_validator(mode="after")
    def _evaluated_fields_present(self) -> QuantumOpinion:
        evaluated = (self.verdict, self.p_malicious, self.confidence)
        if self.gate_triggered and any(v is None for v in evaluated):
            raise ValueError("A triggered quantum opinion needs verdict, p_malicious, confidence.")
        if not self.gate_triggered and any(v is not None for v in evaluated):
            raise ValueError("A non-triggered quantum opinion must not carry results.")
        return self


class DetectionResult(HQCModel):
    """Output of the detection stage for one security event."""

    event_id: NonEmptyStr
    model_id: NonEmptyStr
    model_version: NonEmptyStr
    verdict: Verdict
    p_malicious: Probability
    confidence: Probability
    attack_family: str | None = Field(
        default=None, description="Predicted attack family / dataset class, if any."
    )
    family_probabilities: dict[str, Probability] = Field(default_factory=dict)
    quantum: QuantumOpinion | None = None
    latency_ms: float | None = Field(default=None, ge=0.0)

    @property
    def quantum_agrees(self) -> bool | None:
        """True/False when a quantum opinion exists, else None."""
        if self.quantum is None or not self.quantum.gate_triggered:
            return None
        return self.quantum.verdict == self.verdict

    @property
    def needs_additional_evidence(self) -> bool:
        """Classical/quantum disagreement is a request for more evidence."""
        return self.quantum_agrees is False
