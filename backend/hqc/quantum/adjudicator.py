"""Second-opinion adjudicator for events in the classical uncertainty band.

angle features (fitted on the training band sample) -> kernel model -> Platt calibration
(-> p_second) and stacking with the classical probability (-> p_final, evaluation arm).
The classical detector stays the primary decision-maker: the adjudicator only produces a
``QuantumOpinion`` (for quantum kernels) and a disagreement signal.

Artifacts are joblib (pickle-based) files with a SHA-256 integrity check; only load
artifacts this project wrote.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from pydantic import Field

from hqc.common.errors import ModelCheckpointNotFoundError
from hqc.common.schemas.base import HQCModel, UTCDatetime, Verdict, utc_now
from hqc.common.schemas.detection import QuantumOpinion, confidence_from_probability
from hqc.fusion.stacking import PlattCalibrator, StackingFusion
from hqc.quantum.features import AngleFeatures
from hqc.quantum.models import QUANTUM_KINDS, Hyper, ModelKind, TrainedModel, feature_map_for

EXACT_BACKEND = "numpy-exact-statevector (validated against qiskit Statevector)"


class AdjudicatorMetadata(HQCModel):
    kind: str
    hyper: Hyper
    feature_map: str | None
    backend: str
    n_dims: int
    band: str
    band_lower: float
    band_upper: float
    training_rows: int
    training_malicious: int
    sample_seed: int
    cv_balanced_accuracy: float
    n_support: int | None
    dataset_version: str
    classical_model_version: str
    model_version: str
    created_at: UTCDatetime = Field(default_factory=utc_now)
    evaluation_run_id: str | None = None


@dataclass
class AdjudicatorOutput:
    decision: np.ndarray
    p_second: np.ndarray
    p_final: np.ndarray
    seconds: float


@dataclass
class Adjudicator:
    features: AngleFeatures
    model: TrainedModel
    calibrator: PlattCalibrator
    fusion: StackingFusion
    metadata: AdjudicatorMetadata

    def run(self, frame: pd.DataFrame, p_classical: np.ndarray) -> AdjudicatorOutput:
        started = time.perf_counter()
        decision = self.model.decision(self.features.transform(frame))
        p_second = self.calibrator.predict(decision)
        p_final = self.fusion.predict(p_classical, decision)
        return AdjudicatorOutput(decision, p_second, p_final, time.perf_counter() - started)

    def opinion(self, p_second: float, latency_ms: float | None) -> QuantumOpinion:
        if self.model.kind not in QUANTUM_KINDS:
            raise ValueError("Only quantum-kernel adjudicators produce a QuantumOpinion")
        return QuantumOpinion(
            gate_triggered=True,
            verdict=Verdict.MALICIOUS if p_second >= 0.5 else Verdict.BENIGN,
            p_malicious=p_second,
            confidence=confidence_from_probability(p_second),
            backend=self.metadata.backend,
            feature_map=self.metadata.feature_map,
            latency_ms=latency_ms,
        )

    def save(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "adjudicator.joblib"
        joblib.dump(
            {"features": self.features, "model": self.model, "calibrator": self.calibrator,
             "fusion": self.fusion},
            path,
            compress=3,
        )  # fmt: skip
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        meta = {"metadata": self.metadata.model_dump(mode="json"), "sha256": digest}
        (directory / "adjudicator.json").write_text(
            AdjudicatorFile.model_validate(meta).model_dump_json(indent=1) + "\n"
        )
        return path

    @classmethod
    def load(cls, directory: Path) -> Adjudicator:
        path, meta_path = directory / "adjudicator.joblib", directory / "adjudicator.json"
        if not (path.is_file() and meta_path.is_file()):
            raise ModelCheckpointNotFoundError(f"Incomplete adjudicator artifacts in {directory}")
        meta = AdjudicatorFile.model_validate_json(meta_path.read_text())
        if hashlib.sha256(path.read_bytes()).hexdigest() != meta.sha256:
            raise ModelCheckpointNotFoundError(f"Adjudicator {path} failed its integrity check")
        parts = joblib.load(path)
        return cls(parts["features"], parts["model"], parts["calibrator"], parts["fusion"],
                   meta.metadata)  # fmt: skip


class AdjudicatorFile(HQCModel):
    metadata: AdjudicatorMetadata
    sha256: str


def adjudicator_version(kind: ModelKind, hyper: Hyper, fingerprint: str) -> str:
    payload = f"{kind}|{hyper.model_dump_json()}|{fingerprint}"
    return f"{kind}-{hashlib.sha256(payload.encode()).hexdigest()[:12]}"


def describe_feature_map(kind: ModelKind, hyper: Hyper, n_dims: int, reps: int) -> str | None:
    if kind not in QUANTUM_KINDS:
        return None
    return feature_map_for(kind, reps).describe(n_dims, hyper.alpha)
