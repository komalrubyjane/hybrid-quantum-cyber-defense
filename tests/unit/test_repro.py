"""Reproducibility helpers."""

from __future__ import annotations

import random
from pathlib import Path

from hqc.common.repro import environment_info, git_commit, set_global_seed

SHA = "a" * 40


def test_seed_makes_python_random_deterministic() -> None:
    set_global_seed(123)
    first = [random.random() for _ in range(3)]
    set_global_seed(123)
    assert [random.random() for _ in range(3)] == first


def test_environment_info_records_python_and_packages() -> None:
    info = environment_info()
    assert info.python_version.startswith("3.11")
    assert "pydantic" in info.packages


def test_git_commit_variants(tmp_path: Path) -> None:
    assert git_commit(tmp_path) is None  # not a repo
    git = tmp_path / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    assert git_commit(tmp_path) is None  # repo without commits
    (git / "packed-refs").write_text(f"# pack-refs\n{SHA} refs/heads/main\n")
    assert git_commit(tmp_path) == SHA  # packed ref
    (git / "refs" / "heads" / "main").write_text("b" * 40 + "\n")
    assert git_commit(tmp_path) == "b" * 40  # loose ref wins
    (git / "HEAD").write_text("c" * 40)
    assert git_commit(tmp_path) == "c" * 40  # detached HEAD
