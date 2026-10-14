"""Kernels and kernel diagnostics.

- fidelity (quantum) kernel ``K(x, y) = |<psi(x)|psi(y)>|^2`` from exact statevectors;
- classical controls: RBF ``exp(-gamma ||x - y||^2)`` and linear ``x . y``;
- diagnostics: kernel-target alignment, off-diagonal concentration, minimum eigenvalue,
  and the geometric difference ``g(K_C || K_Q)`` (Huang et al., Nat. Commun. 12, 2631, 2021):
  an a-priori indicator of whether the quantum kernel *could* outperform the classical one
  on this data. A small g (close to 1) means the classical kernel can match it.
"""

from __future__ import annotations

import numpy as np
from pydantic import Field

from hqc.common.schemas.base import HQCModel

GEOMETRIC_DIFFERENCE_REGULARISATION = 1e-3


def fidelity_kernel(states_a: np.ndarray, states_b: np.ndarray) -> np.ndarray:
    overlap = states_a @ states_b.conj().T
    kernel: np.ndarray = np.clip(np.abs(overlap) ** 2, 0.0, 1.0)
    return kernel


def rbf_kernel(a: np.ndarray, b: np.ndarray, gamma: float) -> np.ndarray:
    sq = (a * a).sum(1)[:, None] + (b * b).sum(1)[None, :] - 2.0 * a @ b.T
    kernel: np.ndarray = np.exp(-gamma * np.maximum(sq, 0.0))
    return kernel


def linear_kernel(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    kernel: np.ndarray = a @ b.T
    return kernel


class KernelDiagnostics(HQCModel):
    n: int = Field(ge=1)
    target_alignment: float
    offdiagonal_mean: float
    offdiagonal_std: float
    min_eigenvalue: float


def kernel_target_alignment(kernel: np.ndarray, y01: np.ndarray) -> float:
    """<K, yy^T>_F / (||K||_F ||yy^T||_F) with y in {-1, +1}."""
    y = np.where(np.asarray(y01) > 0, 1.0, -1.0)
    target = np.outer(y, y)
    denom = np.linalg.norm(kernel) * np.linalg.norm(target)
    return float((kernel * target).sum() / denom) if denom else 0.0


def kernel_diagnostics(kernel: np.ndarray, y01: np.ndarray) -> KernelDiagnostics:
    n = kernel.shape[0]
    off = kernel[~np.eye(n, dtype=bool)]
    return KernelDiagnostics(
        n=n,
        target_alignment=kernel_target_alignment(kernel, y01),
        offdiagonal_mean=float(off.mean()) if off.size else 0.0,
        offdiagonal_std=float(off.std()) if off.size else 0.0,
        min_eigenvalue=float(np.linalg.eigvalsh((kernel + kernel.T) / 2.0).min()),
    )


def _trace_normalised(kernel: np.ndarray) -> np.ndarray:
    sym = (kernel + kernel.T) / 2.0
    trace = np.trace(sym)
    if trace <= 0:
        raise ValueError("Kernel matrix must have positive trace")
    scaled: np.ndarray = sym * (sym.shape[0] / trace)
    return scaled


def geometric_difference(
    k_classical: np.ndarray,
    k_quantum: np.ndarray,
    regularisation: float = GEOMETRIC_DIFFERENCE_REGULARISATION,
) -> float:
    """g(K_C || K_Q) = sqrt(|| sqrt(K_Q) (K_C + lambda I)^-1 sqrt(K_Q) ||_inf).

    Both kernels are trace-normalised to N first; lambda regularises the inverse.
    """
    if k_classical.shape != k_quantum.shape or k_classical.shape[0] != k_classical.shape[1]:
        raise ValueError("Kernels must be square and of equal shape")
    kc = _trace_normalised(k_classical)
    kq = _trace_normalised(k_quantum)
    w, v = np.linalg.eigh(kq)
    sqrt_kq = (v * np.sqrt(np.clip(w, 0.0, None))) @ v.T
    inv_kc = np.linalg.inv(kc + regularisation * np.eye(kc.shape[0]))
    middle = sqrt_kq @ inv_kc @ sqrt_kq
    spectral = float(np.linalg.eigvalsh((middle + middle.T) / 2.0).max())
    return float(np.sqrt(max(spectral, 0.0)))
