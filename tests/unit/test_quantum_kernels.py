"""Feature maps (validated against Qiskit), kernels and kernel diagnostics."""

from __future__ import annotations

import numpy as np
import pytest

from hqc.quantum.feature_maps import (
    FeatureMapSpec,
    qiskit_statevectors,
    statevectors,
)
from hqc.quantum.kernels import (
    fidelity_kernel,
    geometric_difference,
    kernel_diagnostics,
    kernel_target_alignment,
    linear_kernel,
    rbf_kernel,
)
from hqc.quantum.noise import NoiseSetting, NoisyKernelEstimator


@pytest.mark.parametrize("kind", ["zz", "z"])
@pytest.mark.parametrize("n_qubits", [2, 3, 5])
@pytest.mark.parametrize("reps", [1, 2])
def test_numpy_statevectors_match_qiskit(kind: str, n_qubits: int, reps: int) -> None:
    spec = FeatureMapSpec(kind=kind, reps=reps)  # type: ignore[arg-type]
    angles = np.random.default_rng(n_qubits * 10 + reps).uniform(0, np.pi, (4, n_qubits))
    ours = statevectors(angles, spec)
    reference = qiskit_statevectors(angles, spec)
    np.testing.assert_allclose(ours, reference, atol=1e-10)  # including the global phase
    np.testing.assert_allclose(np.linalg.norm(ours, axis=1), 1.0, atol=1e-12)


def test_statevector_chunking_and_validation() -> None:
    angles = np.random.default_rng(0).uniform(0, np.pi, (7, 3))
    spec = FeatureMapSpec()
    np.testing.assert_allclose(statevectors(angles, spec, chunk=2), statevectors(angles, spec))
    with pytest.raises(ValueError, match="at least 2"):
        statevectors(angles[:, :1], spec)
    with pytest.raises(ValueError, match="finite"):
        statevectors(np.array([[np.nan, 1.0]]), spec)
    with pytest.raises(ValueError, match="angles must be"):
        statevectors(np.zeros(3), spec)
    assert statevectors(angles[:, :1], FeatureMapSpec(kind="z")).shape == (7, 2)
    assert spec.describe(8, 0.25) == "zz_feature_map(d=8,reps=2,entanglement=linear),alpha=0.25"
    assert FeatureMapSpec(kind="z").describe(4) == "z_feature_map(d=4,reps=2)"


def test_fidelity_kernel_properties() -> None:
    angles = np.random.default_rng(1).uniform(0, np.pi, (12, 4))
    states = statevectors(angles, FeatureMapSpec())
    k = fidelity_kernel(states, states)
    np.testing.assert_allclose(k, k.T, atol=1e-12)
    np.testing.assert_allclose(np.diag(k), 1.0, atol=1e-12)
    assert k.min() >= 0.0 and k.max() <= 1.0
    assert np.linalg.eigvalsh(k).min() > -1e-10  # positive semi-definite


def test_product_z_map_kernel_is_classically_computable() -> None:
    """reps=1 Z map: K(x, y) = prod_i cos^2(x_i - y_i), a closed-form classical kernel."""
    rng = np.random.default_rng(2)
    a, b = rng.uniform(0, np.pi, (5, 3)), rng.uniform(0, np.pi, (6, 3))
    spec = FeatureMapSpec(kind="z", reps=1)
    k = fidelity_kernel(statevectors(a, spec), statevectors(b, spec))
    closed = np.prod(np.cos(a[:, None, :] - b[None, :, :]) ** 2, axis=2)
    np.testing.assert_allclose(k, closed, atol=1e-12)


def test_classical_kernels() -> None:
    a = np.array([[0.0, 0.0], [1.0, 2.0]])
    np.testing.assert_allclose(rbf_kernel(a, a, 0.5), [[1.0, np.exp(-2.5)], [np.exp(-2.5), 1.0]])
    np.testing.assert_allclose(linear_kernel(a, a), [[0.0, 0.0], [0.0, 5.0]])


def test_diagnostics_and_geometric_difference() -> None:
    y = np.array([0, 0, 1, 1])
    ideal = np.outer(np.where(y > 0, 1.0, -1.0), np.where(y > 0, 1.0, -1.0))
    assert kernel_target_alignment(ideal, y) == pytest.approx(1.0)
    assert kernel_target_alignment(np.zeros((4, 4)), y) == 0.0
    identity = kernel_diagnostics(np.eye(4), y)
    assert identity.offdiagonal_mean == 0.0 and identity.min_eigenvalue == pytest.approx(1.0)
    states = statevectors(np.random.default_rng(3).uniform(0, np.pi, (20, 3)), FeatureMapSpec())
    k = fidelity_kernel(states, states)
    assert geometric_difference(k, k) == pytest.approx(1.0, abs=0.01)  # same kernel -> g ~ 1
    # Identity classical kernel: g = sqrt(lambda_max(K_Q) / (1 + lambda)) with K_Q trace-normalised.
    expected = np.sqrt(np.linalg.eigvalsh(k * 20 / np.trace(k)).max() / (1 + 1e-3))
    assert geometric_difference(np.eye(20), k) == pytest.approx(expected, rel=1e-9)
    assert expected > 1.0
    with pytest.raises(ValueError):
        geometric_difference(np.eye(3), np.eye(4))
    with pytest.raises(ValueError, match="trace"):
        geometric_difference(np.zeros((2, 2)), np.eye(2))


def test_noiseless_shot_kernel_matches_exact() -> None:
    rng = np.random.default_rng(4)
    a, b = rng.uniform(0, 0.5 * np.pi, (4, 2)), rng.uniform(0, 0.5 * np.pi, (3, 2))
    spec = FeatureMapSpec()
    estimator = NoisyKernelEstimator(spec, 2, NoiseSetting(name="shots", shots=20000), seed=1)
    k_train = estimator.train_gram(a)
    k_cross = estimator.cross_gram(b, a)
    exact_train = fidelity_kernel(statevectors(a, spec), statevectors(a, spec))
    exact_cross = fidelity_kernel(statevectors(b, spec), statevectors(a, spec))
    np.testing.assert_allclose(np.diag(k_train), 1.0)
    np.testing.assert_allclose(k_train, k_train.T)
    np.testing.assert_allclose(k_train, exact_train, atol=0.03)
    np.testing.assert_allclose(k_cross, exact_cross, atol=0.03)
    assert estimator.circuits_run == 6 + 12


def test_noise_lowers_the_fidelity_of_identical_inputs() -> None:
    a = np.random.default_rng(5).uniform(0, np.pi, (3, 2))
    spec = FeatureMapSpec()
    noisy = NoisyKernelEstimator(
        spec, 2, NoiseSetting(name="noisy", shots=4000, p1=0.01, p2=0.05, readout=0.03), seed=1
    )
    same = noisy.cross_gram(a, a)
    assert np.all(np.diag(same) < 0.97)  # exact value is 1; noise reduces the estimate
