"""Missing-data behaviour of the runnable evaluation scripts (regression tests).

A missing corpus must be reported as a missing prerequisite with the commands to run, not as a
checksum mismatch; the end-to-end validator must stop cleanly (no KeyError) and must not overwrite
the stored validation record when the intelligence services are unavailable.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from hqc.common.errors import DatasetNotFoundError, HQCError, MalformedSourceDataError
from hqc.common.provenance import ArtifactKind, Manifest, ManifestArtifact, sha256_file
from hqc.config import PROJECT_ROOT, Settings
from hqc.evaluation.prerequisites import (
    EXIT_PREREQUISITE,
    display_path,
    require_processed_corpus,
    run_cli,
)
from hqc.mitre.paths import PROCESSED_ATTACK_FLOW_ARTIFACT_ID, processed_attack_flow_path


def _settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, data_dir=tmp_path / "data")


def _manifest(sha: str | None) -> Manifest:
    if sha is None:
        return Manifest(artifacts=[])
    entry = ManifestArtifact(
        artifact_id=PROCESSED_ATTACK_FLOW_ARTIFACT_ID,
        kind=ArtifactKind.PROCESSED,
        description="processed Attack Flow sequences (test)",
        version="test",
        local_path="data/processed/attack_flow/sequences.json",
        sha256=sha,
    )
    return Manifest(artifacts=[entry])


def test_missing_corpus_is_a_prerequisite_not_a_checksum_error(tmp_path: Path) -> None:
    with pytest.raises(DatasetNotFoundError) as info:
        require_processed_corpus(_settings(tmp_path), _manifest("0" * 64))
    message = str(info.value)
    assert "not found" in message
    assert "scripts/build_attack_flow_corpus.py" in message
    assert "checksum" not in message
    assert str(tmp_path) not in message  # no absolute paths outside the project


def test_corrupted_corpus_is_still_malformed(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    corpus = processed_attack_flow_path(settings)
    corpus.parent.mkdir(parents=True)
    corpus.write_text("[]", encoding="utf-8")
    with pytest.raises(MalformedSourceDataError, match="checksum differs"):
        require_processed_corpus(settings, _manifest("0" * 64))


def test_matching_or_unlisted_corpus_is_returned(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    corpus = processed_attack_flow_path(settings)
    corpus.parent.mkdir(parents=True)
    corpus.write_text("[]", encoding="utf-8")
    assert require_processed_corpus(settings, _manifest(sha256_file(corpus))) == corpus
    assert require_processed_corpus(settings, _manifest(None)) == corpus


def test_run_cli_turns_project_errors_into_one_line(capsys: pytest.CaptureFixture[str]) -> None:
    def missing() -> int:
        raise DatasetNotFoundError("corpus not found")

    def other() -> int:
        raise HQCError("bad config")

    assert run_cli(lambda: 0) == 0
    assert run_cli(missing) == EXIT_PREREQUISITE
    assert "error: missing prerequisite: corpus not found" in capsys.readouterr().err
    assert run_cli(other) == EXIT_PREREQUISITE
    err = capsys.readouterr().err
    assert err.strip() == "error: bad config"
    assert "Traceback" not in err


def test_run_cli_does_not_hide_unexpected_bugs() -> None:
    def bug() -> int:
        raise ZeroDivisionError

    with pytest.raises(ZeroDivisionError):
        run_cli(bug)


def test_display_path_is_project_relative() -> None:
    assert display_path(PROJECT_ROOT / "data" / "x.json") == "data/x.json"
    assert display_path(Path("/somewhere/else/x.json")) == "x.json"


@pytest.mark.parametrize(
    "script", ["evaluation/run_markov_baseline.py", "evaluation/run_sequence_models.py"]
)
def test_scripts_use_the_shared_check_and_cli_wrapper(script: str) -> None:
    text = (PROJECT_ROOT / script).read_text(encoding="utf-8")
    assert "require_processed_corpus(settings, manifest)" in text
    assert "raise SystemExit(run_cli(main))" in text
    # The old logic treated a missing file as a checksum mismatch (sha None != manifest).
    assert "if corpus_path.is_file() else None" not in text
    assert "corpus_sha = sha256_file(corpus_path)" in text  # provenance unchanged


def _load_validator() -> ModuleType:
    path = PROJECT_ROOT / "evaluation" / "validate_end_to_end.py"
    spec = importlib.util.spec_from_file_location("validate_end_to_end_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_validator_stops_cleanly_without_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    validator = _load_validator()
    out = tmp_path / "e2e_validation.json"
    monkeypatch.setattr(validator, "OUT", out)
    monkeypatch.setattr(validator, "PROJECT_ROOT", tmp_path)
    monkeypatch.setenv("HQC_DATA_DIR", str(tmp_path / "empty-data"))
    code = validator.main()
    captured = capsys.readouterr()
    assert code == EXIT_PREREQUISITE
    assert not out.exists()  # the stored validation record is never overwritten by a failed run
    assert "FAIL services load from stored artifacts" in captured.out
    assert "intelligence services unavailable (HTTP 503)" in captured.err
    assert "was not modified" in captured.err
    assert "KeyError" not in captured.err
