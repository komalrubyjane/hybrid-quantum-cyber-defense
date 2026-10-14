"""Exact, batched statevectors of Qiskit's ZZ and Z feature maps (local simulation only).

``zz_feature_map(d, reps, entanglement="linear")`` per repetition applies a Hadamard layer
followed by a circuit that is DIAGONAL in the computational basis:

- ``P(2 x_i)`` on every qubit                       -> phase ``2 x_i b_i``;
- ``CX(i, j) P(2 (pi - x_i)(pi - x_j)) CX(i, j)``   -> phase ``2 phi_ij (b_i XOR b_j)``,
  for linear neighbours ``j = i + 1``.

``z_feature_map`` is the same without the two-qubit terms: a PRODUCT state whose fidelity
kernel factorises over qubits and is classically computable in closed form. It is a control.

The batched NumPy implementation is validated against ``qiskit.quantum_info.Statevector`` of
the Qiskit circuits in the test suite (agreement ~1e-15, including global phase). Inputs are
the final rotation angles, i.e. already multiplied by the bandwidth ``alpha``.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal

import numpy as np
from pydantic import Field

from hqc.common.schemas.base import HQCModel

FeatureMapKind = Literal["zz", "z"]
MAX_QUBITS = 12
DEFAULT_CHUNK = 50_000


class FeatureMapSpec(HQCModel):
    kind: FeatureMapKind = "zz"
    reps: int = Field(default=2, ge=1)
    entanglement: Literal["linear"] = "linear"

    def describe(self, n_qubits: int, alpha: float | None = None) -> str:
        name = "zz_feature_map" if self.kind == "zz" else "z_feature_map"
        ent = f",entanglement={self.entanglement}" if self.kind == "zz" else ""
        bw = "" if alpha is None else f",alpha={alpha:g}"
        return f"{name}(d={n_qubits},reps={self.reps}{ent}){bw}"


@lru_cache(maxsize=MAX_QUBITS)
def computational_bits(n_qubits: int) -> np.ndarray:
    """bits[k, i] = value of qubit i in basis state k (Qiskit little-endian order)."""
    index = np.arange(2**n_qubits)
    bits: np.ndarray = ((index[:, None] >> np.arange(n_qubits)) & 1).astype(np.float64)
    return bits


@lru_cache(maxsize=MAX_QUBITS)
def hadamard_layer(n_qubits: int) -> np.ndarray:
    h = np.array([[1.0, 1.0], [1.0, -1.0]]) / np.sqrt(2.0)
    layer = np.array([[1.0]])
    for _ in range(n_qubits):
        layer = np.kron(layer, h)
    return layer


def _phases(angles: np.ndarray, spec: FeatureMapSpec) -> np.ndarray:
    bits = computational_bits(angles.shape[1])
    phase: np.ndarray = 2.0 * angles @ bits.T
    if spec.kind == "zz":
        for i in range(angles.shape[1] - 1):
            phi = (np.pi - angles[:, i]) * (np.pi - angles[:, i + 1])
            parity = np.abs(bits[:, i] - bits[:, i + 1])
            phase += 2.0 * phi[:, None] * parity[None, :]
    return phase


def statevectors(
    angles: np.ndarray, spec: FeatureMapSpec, chunk: int = DEFAULT_CHUNK
) -> np.ndarray:
    """Statevectors (n, 2**d) of the feature map for each row of ``angles`` (n, d)."""
    angles = np.asarray(angles, dtype=np.float64)
    if angles.ndim != 2 or not 1 <= angles.shape[1] <= MAX_QUBITS:
        raise ValueError(f"angles must be (n, d) with 1 <= d <= {MAX_QUBITS}")
    if spec.kind == "zz" and angles.shape[1] < 2:
        raise ValueError("The ZZ feature map needs at least 2 qubits")
    if not np.all(np.isfinite(angles)):
        raise ValueError("angles must be finite")
    n, d = angles.shape
    layer = hadamard_layer(d).T
    out = np.empty((n, 2**d), dtype=np.complex128)
    for start in range(0, n, chunk):
        block = angles[start : start + chunk]
        rotation = np.exp(1j * _phases(block, spec))
        psi = np.zeros((len(block), 2**d), dtype=np.complex128)
        psi[:, 0] = 1.0
        for _ in range(spec.reps):
            psi = (psi @ layer) * rotation
        out[start : start + len(block)] = psi
    return out


def qiskit_feature_map(spec: FeatureMapSpec, n_qubits: int, prefix: str = "x") -> Any:
    """The reference Qiskit circuit (Qiskit 2.x function API)."""
    from qiskit.circuit.library import z_feature_map, zz_feature_map

    if spec.kind == "zz":
        return zz_feature_map(
            n_qubits, reps=spec.reps, entanglement=spec.entanglement, parameter_prefix=prefix
        )
    return z_feature_map(n_qubits, reps=spec.reps, parameter_prefix=prefix)


def qiskit_statevectors(angles: np.ndarray, spec: FeatureMapSpec) -> np.ndarray:
    """Reference statevectors from Qiskit (slow; used for validation only)."""
    from qiskit.quantum_info import Statevector

    circuit = qiskit_feature_map(spec, angles.shape[1])
    rows = [
        Statevector(circuit.assign_parameters(list(row))).data
        for row in np.asarray(angles, dtype=np.float64)
    ]
    return np.asarray(rows, dtype=np.complex128)
