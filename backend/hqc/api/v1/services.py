"""Service container for the API: the Milestone 7 pipeline, loaded lazily (no training).

The real services need the local ATT&CK knowledge base and the stored Milestone 3/4 model
artifacts. If they are missing the API answers 503 (without revealing filesystem paths)
instead of failing at start-up; ``/health`` keeps working.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

from hqc.common.errors import HQCError
from hqc.config import PROJECT_ROOT, Settings
from hqc.pipeline.config import build_pipeline, load_integration_config
from hqc.pipeline.intelligence import IntelligencePipeline

DEFAULT_INTEGRATION_CONFIG = PROJECT_ROOT / "configs" / "integration.yaml"


class ServicesUnavailableError(RuntimeError):
    """The intelligence services cannot be loaded (local artifacts missing)."""


@dataclass(frozen=True)
class ApiServices:
    pipeline: IntelligencePipeline
    attack_version: str
    vocabulary_version: str
    scenario_path: Path | None


class ServiceProvider:
    """Builds the services once, on first use, and caches them (thread-safe)."""

    def __init__(
        self,
        settings: Settings,
        services: ApiServices | None = None,
        config_path: Path = DEFAULT_INTEGRATION_CONFIG,
    ) -> None:
        self._settings = settings
        self._services = services
        self._config_path = config_path
        self._lock = threading.Lock()

    def get(self) -> ApiServices:
        with self._lock:
            if self._services is None:
                self._services = self._build()
            return self._services

    def _build(self) -> ApiServices:
        try:
            config = load_integration_config(self._config_path)
            built = build_pipeline(config, self._settings, PROJECT_ROOT)
        except (HQCError, OSError, ValueError, KeyError, StopIteration) as exc:
            raise ServicesUnavailableError(
                "Intelligence services unavailable: the local ATT&CK knowledge base or stored "
                "prediction artifacts are missing or invalid (see docs/API.md)."
            ) from exc
        return ApiServices(
            pipeline=built.pipeline,
            attack_version=built.catalog.attack_version,
            vocabulary_version=built.vocabulary.vocabulary_version,
            scenario_path=PROJECT_ROOT / config.scenario,
        )
