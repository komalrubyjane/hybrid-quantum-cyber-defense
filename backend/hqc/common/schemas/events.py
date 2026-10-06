"""Security event contracts.

``SecurityEvent`` is a discriminated union over the concrete event types, keyed by
``event_type``. Use :func:`parse_security_event` to validate untrusted input.
"""

from __future__ import annotations

from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any, Literal

from pydantic import Field, TypeAdapter, ValidationError, field_validator

from hqc.common.errors import InvalidEventSchemaError
from hqc.common.schemas.base import (
    DataOrigin,
    HQCModel,
    NonEmptyStr,
    UTCDatetime,
    check_finite_mapping,
)

IPAddress = IPv4Address | IPv6Address
Port = Annotated[int, Field(ge=0, le=65535)]


class BaseSecurityEvent(HQCModel):
    """Fields shared by every security event."""

    event_id: NonEmptyStr
    timestamp: UTCDatetime
    source_dataset: NonEmptyStr = Field(
        description="Dataset or feed identifier, e.g. 'cicids2017' or 'synthetic-basic'."
    )
    data_origin: DataOrigin
    entity_id: NonEmptyStr = Field(description="Primary entity (host, IP or account) concerned.")
    ground_truth_label: str | None = Field(
        default=None,
        description="Dataset label. For evaluation only; never used as a model input.",
    )


class NetworkFlow(BaseSecurityEvent):
    """A network flow record (e.g. one CIC-IDS2017 / UNSW-NB15 row)."""

    event_type: Literal["network_flow"] = "network_flow"
    src_ip: IPAddress | None = None
    dst_ip: IPAddress | None = None
    src_port: Port | None = None
    dst_port: Port | None = None
    protocol: str | None = None
    duration_s: float | None = Field(default=None, ge=0.0, allow_inf_nan=False)
    features: dict[str, float] = Field(
        default_factory=dict,
        description="Numeric flow features keyed by the dataset's canonical feature name.",
    )

    @field_validator("features")
    @classmethod
    def _finite_features(cls, value: dict[str, float]) -> dict[str, float]:
        return check_finite_mapping(value, "features")


class AuthOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class AuthenticationEvent(BaseSecurityEvent):
    """An authentication attempt. Credentials are never part of this schema."""

    event_type: Literal["authentication"] = "authentication"
    user: NonEmptyStr
    outcome: AuthOutcome
    src_ip: IPAddress | None = None
    target_host: str | None = None
    auth_method: str | None = None


class SystemEvent(BaseSecurityEvent):
    """A host-level event (process, service, file or configuration activity)."""

    event_type: Literal["system"] = "system"
    host: NonEmptyStr
    action: NonEmptyStr = Field(description="Normalised action, e.g. 'process_start'.")
    process_name: str | None = None
    user: str | None = None
    details: dict[str, str] = Field(default_factory=dict)


class APIEvent(BaseSecurityEvent):
    """An application / API gateway request event."""

    event_type: Literal["api"] = "api"
    client_id: NonEmptyStr
    endpoint: NonEmptyStr
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    status_code: int = Field(ge=100, le=599)
    src_ip: IPAddress | None = None
    bytes_out: int | None = Field(default=None, ge=0)


SecurityEvent = Annotated[
    NetworkFlow | AuthenticationEvent | SystemEvent | APIEvent,
    Field(discriminator="event_type"),
]
"""Any supported security event (discriminated on ``event_type``)."""

_EVENT_ADAPTER: TypeAdapter[SecurityEvent] = TypeAdapter(SecurityEvent)


def parse_security_event(payload: dict[str, Any] | str | bytes) -> SecurityEvent:
    """Validate a dict or JSON payload into a concrete event.

    Raises:
        InvalidEventSchemaError: if the payload does not match any event schema.
    """
    try:
        if isinstance(payload, str | bytes):
            return _EVENT_ADAPTER.validate_json(payload)
        return _EVENT_ADAPTER.validate_python(payload)
    except ValidationError as exc:
        raise InvalidEventSchemaError(str(exc)) from exc
