"""Project exception hierarchy.

Every failure mode named in the project requirements has a dedicated exception so
callers can fail loudly instead of continuing with incorrect data.
"""

from __future__ import annotations


class HQCError(Exception):
    """Base class for all project errors."""


class ConfigurationError(HQCError):
    """Invalid or inconsistent configuration."""


class UnsupportedAttackVersionError(ConfigurationError):
    """The requested MITRE ATT&CK version is malformed or not available locally."""


class InvalidTechniqueIdError(HQCError, ValueError):
    """A string is not a valid ATT&CK technique ID, or is unknown to the knowledge base."""


class InvalidEventSchemaError(HQCError, ValueError):
    """An incoming security event does not match the expected schema."""


class DatasetNotFoundError(HQCError, FileNotFoundError):
    """A required dataset is missing. Datasets are never downloaded automatically."""


class FeatureSchemaMismatchError(HQCError, ValueError):
    """Features presented to a model do not match the schema it was trained on."""


class ModelCheckpointNotFoundError(HQCError, FileNotFoundError):
    """A required model checkpoint or its metadata is missing."""


class QuantumBackendUnavailableError(HQCError, RuntimeError):
    """The configured (local) quantum simulator backend cannot be used."""


class DataLeakageError(HQCError, ValueError):
    """Training and evaluation data overlap (e.g. a source document appears in both)."""


class RecordNotFoundError(HQCError, KeyError):
    """A record requested from storage does not exist."""


class StorageError(HQCError):
    """A storage operation violated a storage rule (e.g. overwriting a write-once record)."""


class MalformedSourceDataError(HQCError, ValueError):
    """External source data (ATT&CK STIX, Attack Flow, manifests) is structurally invalid."""


class MissingRequiredFieldError(MalformedSourceDataError):
    """A required field is absent from external source data."""


class UnknownTechniqueError(InvalidTechniqueIdError):
    """A well-formed technique ID that does not exist in the loaded ATT&CK knowledge base."""


class UntrustedSourceError(HQCError, ValueError):
    """A download URL is not on the allowlist of official sources."""
