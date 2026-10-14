"""Noisy, shot-based fidelity-kernel estimation with Qiskit Aer (local simulation only).

K(x, y) is estimated as the frequency of the all-zeros outcome of the compute-uncompute
circuit ``U(x) U(y)^dagger`` over ``shots`` shots, under an Aer ``NoiseModel`` with
depolarizing errors on 1-qubit (p1) and 2-qubit (p2) gates and symmetric readout error. The
training Gram diagonal is set to 1 (as Qiskit's fidelity kernels do by default). Used only
for the small noise-robustness study; the main experiments use exact statevectors.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from pydantic import Field

from hqc.common.schemas.base import HQCModel
from hqc.quantum.feature_maps import FeatureMapSpec, qiskit_feature_map

BASIS_GATES = ["rz", "sx", "x", "cx"]
SINGLE_QUBIT_GATES = ["rz", "sx", "x"]
BIND_CHUNK = 20_000


class NoiseSetting(HQCModel):
    name: str
    shots: int = Field(ge=1)
    p1: float = Field(default=0.0, ge=0.0, le=1.0)
    p2: float = Field(default=0.0, ge=0.0, le=1.0)
    readout: float = Field(default=0.0, ge=0.0, lt=0.5)


def _noise_model(setting: NoiseSetting) -> Any:
    if setting.p1 == 0 and setting.p2 == 0 and setting.readout == 0:
        return None
    from qiskit_aer.noise import NoiseModel, ReadoutError, depolarizing_error

    model = NoiseModel(basis_gates=BASIS_GATES)
    if setting.p1:
        model.add_all_qubit_quantum_error(depolarizing_error(setting.p1, 1), SINGLE_QUBIT_GATES)
    if setting.p2:
        model.add_all_qubit_quantum_error(depolarizing_error(setting.p2, 2), ["cx"])
    if setting.readout:
        r = setting.readout
        model.add_all_qubit_readout_error(ReadoutError([[1 - r, r], [r, 1 - r]]))
    return model


class NoisyKernelEstimator:
    def __init__(self, spec: FeatureMapSpec, n_qubits: int, setting: NoiseSetting, seed: int):
        from qiskit import QuantumCircuit, transpile
        from qiskit_aer import AerSimulator

        left = qiskit_feature_map(spec, n_qubits, prefix="a")
        right = qiskit_feature_map(spec, n_qubits, prefix="b")
        circuit = QuantumCircuit(n_qubits)
        circuit.compose(left, inplace=True)
        circuit.compose(right.inverse(), inplace=True)
        circuit.measure_all()
        self.circuit = transpile(
            circuit, basis_gates=BASIS_GATES, optimization_level=0, seed_transpiler=seed
        )
        self.simulator = AerSimulator(
            method="density_matrix", noise_model=_noise_model(setting), seed_simulator=seed
        )
        self.setting = setting
        self.n_qubits = n_qubits
        self.zeros = "0" * n_qubits
        self.circuits_run = 0

    def _estimate(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        out = np.empty(len(a), dtype=np.float64)
        params = list(self.circuit.parameters)
        for start in range(0, len(a), BIND_CHUNK):
            sa, sb = a[start : start + BIND_CHUNK], b[start : start + BIND_CHUNK]
            binds = {p: (sa if p.vector.name == "a" else sb)[:, p.index].tolist() for p in params}
            result = self.simulator.run(
                self.circuit, parameter_binds=[binds], shots=self.setting.shots
            ).result()
            for i in range(len(sa)):
                out[start + i] = result.get_counts(i).get(self.zeros, 0) / self.setting.shots
        self.circuits_run += len(a)
        return out

    def train_gram(self, angles: np.ndarray) -> np.ndarray:
        n = len(angles)
        i, j = np.triu_indices(n, k=1)
        kernel = np.eye(n)
        values = self._estimate(angles[i], angles[j])
        kernel[i, j] = values
        kernel[j, i] = values
        return kernel

    def cross_gram(self, angles_a: np.ndarray, angles_b: np.ndarray) -> np.ndarray:
        i, j = np.meshgrid(np.arange(len(angles_a)), np.arange(len(angles_b)), indexing="ij")
        values = self._estimate(angles_a[i.ravel()], angles_b[j.ravel()])
        return values.reshape(len(angles_a), len(angles_b))
