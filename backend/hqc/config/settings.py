"""Application settings.

Precedence (highest first):
    1. keyword arguments passed to ``Settings(...)`` (used in tests)
    2. environment variables (``HQC_*``; ATT&CK version also via ``ATTACK_VERSION``)
    3. ``.env`` file in the project root
    4. YAML defaults file (``configs/default.yaml`` or ``$HQC_CONFIG_FILE``)
    5. field defaults below
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from hqc.common.errors import UnsupportedAttackVersionError

PROJECT_ROOT: Path = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG_FILE: Path = PROJECT_ROOT / "configs" / "default.yaml"
ATTACK_VERSION_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}$")

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def _config_file() -> Path:
    override = os.environ.get("HQC_CONFIG_FILE")
    return Path(override) if override else DEFAULT_CONFIG_FILE


class Settings(BaseSettings):
    """Typed, validated runtime configuration."""

    model_config = SettingsConfigDict(
        env_prefix="HQC_",
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="forbid",
        frozen=True,
    )

    environment: Literal["development", "test", "research"] = "development"
    seed: int = Field(default=42, ge=0)

    attack_version: str = Field(
        default="19.2",
        validation_alias=AliasChoices("ATTACK_VERSION", "HQC_ATTACK_VERSION", "attack_version"),
        description="MITRE ATT&CK Enterprise version (MAJOR.MINOR). Must be verified "
        "against the official release before building the knowledge base.",
    )
    attack_domain: Literal["enterprise-attack"] = "enterprise-attack"

    data_dir: Path = Path("data")
    models_dir: Path = Path("models")
    reports_dir: Path = Path("reports")
    db_path: Path = Path("data/hqc.sqlite3")

    log_level: LogLevel = "INFO"
    log_json: bool = True

    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    @field_validator("attack_version")
    @classmethod
    def _validate_attack_version(cls, value: str) -> str:
        value = value.strip().removeprefix("v")
        if not ATTACK_VERSION_PATTERN.match(value):
            raise UnsupportedAttackVersionError(
                f"ATT&CK version must look like MAJOR.MINOR (e.g. '19.2'); got {value!r}"
            )
        return value

    @field_validator("cors_origins")
    @classmethod
    def _no_wildcard_cors(cls, value: list[str]) -> list[str]:
        if "*" in value:
            raise ValueError("Wildcard CORS origins are not allowed; list explicit origins.")
        return value

    def resolve(self, path: Path) -> Path:
        """Resolve a configured path relative to the project root."""
        return path if path.is_absolute() else PROJECT_ROOT / path

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        yaml_settings = YamlConfigSettingsSource(settings_cls, yaml_file=_config_file())
        return (init_settings, env_settings, dotenv_settings, yaml_settings)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance (cached)."""
    return Settings()
