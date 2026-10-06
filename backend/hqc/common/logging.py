"""Structured logging with secret redaction.

Use ``get_logger(__name__)`` and pass context via ``extra``::

    log.info("prediction complete", extra={"stage": "prediction", "chain_id": cid})

Values whose key looks sensitive (password, token, api_key, secret, credential,
authorization, ...) are replaced with ``[REDACTED]`` before formatting, both in
``extra`` fields and in ``key=value`` / ``key: value`` fragments of the message.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

REDACTED = "[REDACTED]"
SENSITIVE_KEY_PATTERN = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|credential|authorization|private[_-]?key|cookie)",
    re.IGNORECASE,
)
_INLINE_SECRET_PATTERN = re.compile(
    r"(?P<key>\b[\w-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|credential|authorization)"
    r"[\w-]*)(?P<sep>\s*[=:]\s*)(?P<value>[^\s,;]+)",
    re.IGNORECASE,
)

# Attributes present on every LogRecord; anything else came from ``extra``.
_STANDARD_ATTRS = frozenset(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


def redact_text(text: str) -> str:
    """Mask ``key=value`` / ``key: value`` fragments whose key looks sensitive."""
    return _INLINE_SECRET_PATTERN.sub(lambda m: f"{m['key']}{m['sep']}{REDACTED}", text)


def redact_value(key: str, value: Any) -> Any:
    """Recursively redact a structured value given its key."""
    if SENSITIVE_KEY_PATTERN.search(key):
        return REDACTED
    if isinstance(value, dict):
        return {k: redact_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact_value(key, v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


class RedactingFilter(logging.Filter):
    """Redacts sensitive data in the message and in ``extra`` attributes."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage())
        record.args = None
        for key in list(vars(record)):
            if key not in _STANDARD_ATTRS:
                setattr(record, key, redact_value(key, getattr(record, key)))
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line: timestamp, level, logger, message and extra fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS:
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, sort_keys=False)


class _ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = {k: v for k, v in vars(record).items() if k not in _STANDARD_ATTRS}
        return f"{base} {extras}" if extras else base


_HANDLER_NAME = "hqc-root-handler"


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    """Configure the ``hqc`` logger hierarchy. Idempotent."""
    logger = logging.getLogger("hqc")
    logger.setLevel(level)
    logger.propagate = False
    for handler in list(logger.handlers):
        if handler.get_name() == _HANDLER_NAME:
            logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.set_name(_HANDLER_NAME)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(
        JsonFormatter()
        if json_output
        else _ConsoleFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a logger inside the ``hqc`` hierarchy."""
    return logging.getLogger(name if name.startswith("hqc") else f"hqc.{name}")
