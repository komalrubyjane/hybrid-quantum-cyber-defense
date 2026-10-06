"""Configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from hqc.common.errors import UnsupportedAttackVersionError
from hqc.config import PROJECT_ROOT, Settings, get_settings


def _settings(**kwargs: object) -> Settings:
    return Settings(_env_file=None, **kwargs)  # type: ignore[arg-type]


def test_yaml_defaults_loaded() -> None:
    s = _settings()
    assert s.attack_version == "19.2"
    assert s.seed == 42
    assert s.attack_domain == "enterprise-attack"


def test_attack_version_from_plain_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATTACK_VERSION", "18.1")
    assert _settings().attack_version == "18.1"


def test_prefixed_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HQC_SEED", "7")
    monkeypatch.setenv("HQC_LOG_LEVEL", "DEBUG")
    s = _settings()
    assert s.seed == 7
    assert s.log_level == "DEBUG"


def test_attack_version_v_prefix_normalised() -> None:
    assert _settings(attack_version="v19.2").attack_version == "19.2"


@pytest.mark.parametrize("bad", ["19", "latest", "19.2.1", "nineteen"])
def test_malformed_attack_version_rejected(bad: str) -> None:
    with pytest.raises(UnsupportedAttackVersionError):
        _settings(attack_version=bad)


def test_wildcard_cors_rejected() -> None:
    with pytest.raises(ValidationError):
        _settings(cors_origins=["*"])


def test_unknown_setting_rejected() -> None:
    with pytest.raises(ValidationError):
        _settings(not_a_setting=1)


def test_custom_yaml_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("seed: 123\nattack_version: '17.1'\n")
    monkeypatch.setenv("HQC_CONFIG_FILE", str(cfg))
    s = _settings()
    assert (s.seed, s.attack_version) == (123, "17.1")


def test_relative_paths_resolve_against_project_root() -> None:
    s = _settings()
    assert s.resolve(s.data_dir) == PROJECT_ROOT / "data"
    assert s.resolve(Path("/abs")) == Path("/abs")


def test_settings_are_frozen() -> None:
    s = _settings()
    with pytest.raises(ValidationError):
        s.seed = 1


def test_get_settings_cached() -> None:
    assert get_settings() is get_settings()
