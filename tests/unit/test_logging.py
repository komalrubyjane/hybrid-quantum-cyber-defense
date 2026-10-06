"""Structured logging and secret redaction."""

from __future__ import annotations

import json
import logging

import pytest

from hqc.common.logging import (
    REDACTED,
    JsonFormatter,
    RedactingFilter,
    configure_logging,
    get_logger,
    redact_text,
    redact_value,
)


def _format(record: logging.LogRecord) -> dict[str, object]:
    RedactingFilter().filter(record)
    out: dict[str, object] = json.loads(JsonFormatter().format(record))
    return out


def _record(msg: str, **extra: object) -> logging.LogRecord:
    record = logging.makeLogRecord({"name": "hqc.test", "levelname": "INFO", "msg": msg})
    for k, v in extra.items():
        setattr(record, k, v)
    return record


def test_json_output_contains_structured_fields() -> None:
    out = _format(_record("chain built", stage="attack_chain", chain_id="c-1"))
    assert out["message"] == "chain built"
    assert out["stage"] == "attack_chain"
    assert out["chain_id"] == "c-1"
    assert "ts" in out and out["level"] == "INFO"


@pytest.mark.parametrize(
    "text",
    ["password=hunter2", "api_key: abc123", "Authorization=Bearer-xyz", "db_token=t0k"],
)
def test_inline_secrets_redacted(text: str) -> None:
    redacted = redact_text(text)
    assert REDACTED in redacted
    assert text.split("=")[-1].split(":")[-1].strip() not in redacted


def test_extra_fields_with_sensitive_keys_redacted() -> None:
    out = _format(_record("login", password="hunter2", user="alice", config={"api_key": "k"}))
    assert out["password"] == REDACTED
    assert out["user"] == "alice"
    assert out["config"] == {"api_key": REDACTED}


def test_message_args_redacted() -> None:
    record = logging.makeLogRecord(
        {"name": "hqc.t", "levelname": "INFO", "msg": "conn %s", "args": ("secret=s3",)}
    )
    out = _format(record)
    assert "s3" not in str(out["message"])


def test_non_sensitive_text_untouched() -> None:
    assert redact_text("technique=T1059 confidence=0.8") == "technique=T1059 confidence=0.8"
    assert redact_value("score", 0.5) == 0.5


def test_configure_logging_idempotent() -> None:
    configure_logging("INFO", json_output=True)
    configure_logging("DEBUG", json_output=False)
    root = logging.getLogger("hqc")
    assert len(root.handlers) == 1
    assert root.level == logging.DEBUG
    assert get_logger("x").name == "hqc.x"
    assert get_logger("hqc.y").name == "hqc.y"
