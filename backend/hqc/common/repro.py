"""Reproducibility helpers: seeding, environment capture, git commit lookup.

The commit lookup reads ``.git`` files directly; the dirty-tree check runs
``git status --porcelain`` with a fixed argument list (no shell).
"""

from __future__ import annotations

import os
import platform
import random
import subprocess
import sys
from importlib import import_module, metadata
from pathlib import Path

from hqc.common.schemas.evaluation import EnvironmentInfo

# Packages whose versions are recorded in every run (missing ones are skipped).
TRACKED_PACKAGES: tuple[str, ...] = (
    "hqc",
    "pydantic",
    "fastapi",
    "numpy",
    "pandas",
    "scikit-learn",
    "torch",
    "qiskit",
    "qiskit-aer",
    "qiskit-machine-learning",
)


def set_global_seed(seed: int) -> None:
    """Seed Python, and NumPy / PyTorch if they are installed."""
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    try:
        np = import_module("numpy")
        np.random.seed(seed)
    except ImportError:
        pass
    try:
        torch = import_module("torch")
        torch.manual_seed(seed)
        torch.use_deterministic_algorithms(True, warn_only=True)
    except ImportError:
        pass


def package_versions(packages: tuple[str, ...] = TRACKED_PACKAGES) -> dict[str, str]:
    """Return installed versions for the given distribution names."""
    versions: dict[str, str] = {}
    for name in packages:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
    return versions


def environment_info() -> EnvironmentInfo:
    """Capture interpreter, platform and package versions."""
    return EnvironmentInfo(
        python_version=platform.python_version(),
        platform=platform.platform(),
        executable=Path(sys.executable).name,
        packages=package_versions(),
    )


def git_commit(repo_dir: Path) -> str | None:
    """Return the current commit SHA of ``repo_dir`` or None if unavailable.

    Handles detached HEAD, loose refs and packed refs. Returns None for a repository
    without commits.
    """
    git_dir = repo_dir / ".git"
    head_file = git_dir / "HEAD"
    if not head_file.is_file():
        return None
    head = head_file.read_text(encoding="utf-8").strip()
    if not head.startswith("ref:"):
        return head or None
    ref = head.removeprefix("ref:").strip()
    loose = git_dir / ref
    if loose.is_file():
        return loose.read_text(encoding="utf-8").strip() or None
    packed = git_dir / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0]
    return None


GIT_STATUS_TIMEOUT_S = 10


def git_working_tree_dirty(repo_dir: Path) -> bool | None:
    """True if ``git status --porcelain`` reports changes, None if git is unavailable.

    Ignored files (datasets, generated artifacts) are not counted. Uses a fixed
    argument list (no shell). This helper lives in ``hqc.common``; the defense package
    never runs processes.
    """
    if not (repo_dir / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=GIT_STATUS_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return bool(result.stdout.strip())
